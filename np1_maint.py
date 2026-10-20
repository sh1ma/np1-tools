#!/usr/bin/env python3
"""NP1 Maintenance Mode クライアント。

APK (jp.pioneer.npapp 1.6.3) の BLE 実装と、チップオフした eMMC から取り出した
本体ファームウェア (/usr/local/bin/System) を突き合わせて再実装したもの。

ペアリング (Opcode 2/8/10) から Maintenance Mode 入場
(Function 0xE000 / Opcode 1 → 0x8002 → Opcode 4) までを一本で通す。

プロトコル根拠:
  - PDU 組み立てと署名      : k4/a.java k0(), ed/i.java m0(), ed/a.java
  - 応答パース              : k4/a.java s0()
  - requestId 採番          : hc/a.java i()
  - Opcode 2/8              : ed/n.java b(), c()
  - Opcode 3/4/10           : ed/i.java
  - EdgeSystemState         : ed/i.java
  - Function 0xE000 の仕様  : System バイナリ CDBG_SRV_DBG_AppCooperation
                              および .rodata 0x19FA10 の FileDescriptorProto
  ペアリングと Maintenance Mode の手順は docs/np1-overview.md を参照。
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import shlex
import struct
import sys
import time
import urllib.error
import urllib.request
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from collections.abc import Awaitable
from typing import Any, Callable

from np1_transport import (
    TransportError,
    gatt_error_types,
    make_transport,
    CONTROL_POINT,
    DATA_SOURCE,
    EDGE_SYSTEM_STATE,
    NOTIFICATION_SOURCE,
    SECURE_CONTROL_POINT,
    SECURE_DATA_SOURCE,
    SECURE_NOTIFICATION_SOURCE,
)

# --------------------------------------------------------------------------
# 定数
# --------------------------------------------------------------------------

LOGIN_URL = (
    "https://sp01.prd.pioneerapis.com/"
    "simbareverseproxy/client/api/v1/token/accesstoken"
)
# 本体の URL テーブル (etc/Resource/server/URL00000000.dat) の AUTH_CREATE_TOKEN は
# a01-04000000.obd.pioneerapis.com 側だが、そちらは外から叩くと経路ごと
# Not Found(SRP) になる。アプリと同じ sp01 から取った member token を
# EdgeInfo LOGIN_REQUEST で本体へ渡すと、本体が自分で a01 を使う。
MEMBER_TOKEN_URL = (
    "https://sp01.prd.pioneerapis.com/"
    "simbareverseproxy/client/api/v1/token/members/accesstoken"
)
DEFAULT_USER_AGENT = "MobileAppNp1/1.6.3 Android/15.0"


# ed/c.java: 接続 callback 後 1,000 ms 待ってから service discovery
POST_CONNECT_DELAY_SECONDS = 1.0
# ed/i.java: write ACK 待ち 10,000 ms、合計 4 回で RETRY_OVER
WRITE_ACK_TIMEOUT_SECONDS = 10.0
WRITE_ATTEMPTS = 4

# FW 7.000010 Communication (BuildID fe54f987...) の
# CCOM_FreeStyleLinkService::OnInitialize は、credential dirty flag を検査して
# /SETUP/FreeStyleLink/devices.dat へ保存する周期 timer を 60,000 ms で開始する
# (0x0af184..0x0af19c, ExpirationCheckTimer 0x0ae158)。
CREDENTIAL_SAVE_INTERVAL_SECONDS = 60.0
# timer 境界と非同期 BackupCredentialTask の起動を跨ぐためのクライアント側猶予。
# ファーム由来の定数ではないので、上の 60 秒とは分けておく。
PERSISTENCE_SCHEDULING_GRACE_SECONDS = 5.0
PAIR_PERSISTENCE_WAIT_SECONDS = (
    CREDENTIAL_SAVE_INTERVAL_SECONDS + PERSISTENCE_SCHEDULING_GRACE_SECONDS
)

# FW 7.000010 Setting (BuildID 0799a4ba...) の StandardSetting は、設定変更ごとに
# 3,000 ms timer を再始動し、満了時に SaveSettingData を queue する
# (0x099a40..0x099a50 -> 0x099348 -> 0x0de518)。
SETTING_SAVE_DEBOUNCE_SECONDS = 3.0
SETTING_SAVE_WAIT_SECONDS = (
    SETTING_SAVE_DEBOUNCE_SECONDS + PERSISTENCE_SCHEDULING_GRACE_SECONDS
)

def state_dir() -> Path:
    """Linux での session.json と socket の置き場。"""
    return Path(
        os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state")
    ) / "np1"


DEFAULT_SOCKET_PATH = state_dir() / "np1.sock"
DEFAULT_SESSION_PATH = state_dir() / "session.json"

# ba/o.java
BLE_ERRORS = {
    0: "UNKNOWN_ERROR",
    1: "ACCESS_TOKEN_EXPIRED",
    2: "INVALID_ACCESS_TOKEN",
    3: "INVALID_TIMESTAMP",
    4: "INVALID_SIGNATURE",
    5: "INVALID_ARGUMENT",
    6: "FUNCTION_UNAVAILABLE",
}

# --- Function 0x0200: InitialSetup ---------------------------------------
# FW 7.000010 Setting の InitialSetup.proto とハンドラ
# (0x08d980 status request / 0x08dab0 finished notify) より。
FUNC_INITIAL_SETUP = 0x0200
OP_INITIAL_SETUP_STATUS_REQUEST = 1
OP_INITIAL_SETUP_STATUS_RESPONSE = 0x8001
OP_INITIAL_SETUP_FINISHED_NOTIFY = 2

INITIAL_SETUP_FINISHED = 1
INITIAL_SETUP_FINISHED_EXCEPT_COMMUNICATION = 2
INITIAL_SETUP_NOT_FINISHED = 3
INITIAL_SETUP_STATUSES = {
    0: "DEFAULT",
    INITIAL_SETUP_FINISHED: "FINISHED",
    INITIAL_SETUP_FINISHED_EXCEPT_COMMUNICATION:
        "FINISHED_EXCEPT_COMMUNICATION_SETTING",
    INITIAL_SETUP_NOT_FINISHED: "NOT_FINISHED",
}

# --- Function 0x0400: VolumeSetting -------------------------------------
# FW 7.000010 Setting の VolumeSetting.proto と
# OnVolumeSettingMuteNotify (0x08eb68..0x08ed10) より。
FUNC_VOLUME_SETTING = 0x0400
OP_VOLUME_SETTING_REQUEST = 1
OP_VOLUME_SETTING_RESPONSE = 0x8001
OP_MASTER_VOLUME_REQUEST = 2
OP_MASTER_VOLUME_RESPONSE = 0x8002
OP_MUTE_REQUEST = 3
OP_MUTE_RESPONSE = 0x8003

COMMON_OFF = 1
COMMON_ON = 2
COMMON_ON_OFF = {0: "DEFAULT", COMMON_OFF: "OFF", COMMON_ON: "ON"}

# --- Function 0xE000: MaintenanceEntryExit -------------------------------
# System バイナリ .rodata 0x19FA10 の FileDescriptorProto より。
# CommandType の enum 値がそのまま BLE opcode になっている。
FUNC_MAINTENANCE = 0xE000
OP_ENTRY_START_NOTIFY = 1
OP_ENTRY_END_NOTIFY = 3
OP_PASSWORD_VERIFICATION_REQUEST = 4
OP_MAINTENANCE_MODE_REQUEST = 5
OP_COMMAND_INPUT_END_NOTIFY = 0x8002
OP_PASSWORD_VERIFICATION_RESPONSE = 0x8004
OP_MAINTENANCE_MODE_RESPONSE = 0x8005

MAINTENANCE_MODES = {
    0: "DEFAULT",
    1: "OFF",
    2: "POSEIDON",
    3: "APP",  # ファームのログ上は "develop"
    4: "SALES",
    5: "SERVICE",
}

# System バイナリ内で AES-128-CBC 暗号化されていたパスワード
# (IV @0x19f760 / KEY @0x19f770 を使って復号したもの)
MAINTENANCE_PASSWORDS = {
    "poseidon-on": "POSEIDONDBG ON",
    "poseidon-off": "POSEIDONDBG OFF",
    "app-on": "CREATI ON",
    "app-off": "CREATI OFF",
    "service-on": "ADAPTI ON",
    "service-off": "ADAPTI OFF",
    "sales-on": "SUFFUSI ON",
    "sales-off": "SUFFUSI OFF",
}

# --- Function 0xF00D: DebugSerialPortIO ----------------------------------
# System バイナリ .rodata 0x15E140 の FileDescriptorProto より。
# Maintenance Mode に入っていないと受け付けられない。
FUNC_SERIAL_PORT_IO = 0xF00D
OP_SERIAL_GET_REQUEST = 1
OP_SERIAL_LOG_OUTPUT_SWITCH_REQUEST = 2
OP_SERIAL_CONSOLE_INPUT_SWITCH_REQUEST = 3
OP_SERIAL_GET_RESPONSE = 0x8001
OP_SERIAL_LOG_OUTPUT_SWITCH_RESPONSE = 0x8002
OP_SERIAL_CONSOLE_INPUT_SWITCH_RESPONSE = 0x8003

# --- Function 0x0900: ProgramUpdate (OTA) --------------------------------
# Update バイナリ内の ProgramUpdate.proto より。Maintenance Mode は不要。
# CHECK_DATA_REQUEST を送ると、本体が自分の資格情報で OTA サーバーへ
# 問い合わせ、利用可能なバージョンを返す。
FUNC_PROGRAM_UPDATE = 0x0900
OP_CHECK_DATA_REQUEST = 1
OP_CHECK_DATA_RESPONSE = 0x8001
OP_FIRMWARE_DOWNLOAD_START_REQUEST = 2
OP_FIRMWARE_UPDATE_PROGRESS_NOTIFICATION = 0x8002
OP_FIRMWARE_DOWNLOAD_CANCEL_REQUEST = 3
OP_FIRMWARE_UPDATE_ACTIVATE_REQUEST = 4

CHECK_DATA_RESULTS = {
    0: "DEFAULT",
    1: "NO_DATA (更新なし)",
    2: "NEW_DATA_FOUND (新しいデータあり)",
    3: "NEW_DATA_DOWNLOADING (ダウンロード中)",
    4: "NEW_DATA_UPDATING (更新中)",
    5: "NEW_DATA_UPDATE_FINISHED (更新完了)",
    6: "CHECK_FAILED (確認失敗)",
}

# --- Function 0x0302: EdgeInfo (My NP1 アカウントへのログイン状態) --------
# Setting バイナリに埋まっている EdgeInfo.proto より (package EdgeInfo)。
# Maintenance Mode は不要。
#
# 本体は OTA サーバーへの問い合わせに AL_AccountService::GetOwnersToken() で
# 取った owner の token を使う (Update バイナリ .rodata の
# "authorization: Bearer " と "get OwnersToken failed." が同じ関数にある)。
# ログインしていない本体はこの token を作れないので、0x0900/1 CHECK_DATA は
# CHECK_FAILED しか返さない。
FUNC_EDGE_INFO = 0x0302
OP_GET_LOGIN_INFO_REQUEST = 1
OP_GET_LOGIN_INFO_RESPONSE = 0x8001
OP_LOGIN_REQUEST = 2
OP_LOGIN_RESPONSE = 0x8002
OP_CHECK_IN_REQUEST = 3
OP_CHECK_IN_RESPONSE = 0x8003

LOGIN_INFO = {
    0: "DEFAULT",
    1: "LOGGED_IN (ログイン済み)",
    2: "NOT_YET_LOGGED_IN (未ログイン)",
    3: "STARTUP_REFRESH_UNCOMPLETE (起動時 refresh 未完了)",
}

# --- Function 0x0500: WiFiStationMode (外部 AP への STA 接続) -------------
# Communication バイナリ内 proto_STAmode.proto より。Maintenance Mode は不要。
# SIM が入っていない個体を外部 Wi-Fi 経由でインターネットに繋ぐのに使う。
FUNC_WIFI_STA = 0x0500
OP_STA_INFO_REQUEST = 1
OP_STA_SETTING_CHANGE_REQUEST = 2
OP_STA_REGISTERED_AP_LIST_REQUEST = 4
OP_STA_NEARBY_AP_LIST_REQUEST = 5
OP_STA_CONNECTING_AP_REQUEST = 6
OP_STA_DELETE_REGISTERED_AP_REQUEST = 7
OP_STA_CONNECT_REQUEST = 9
OP_STA_DISCONNECT_REQUEST = 10
OP_STA_INIT_REQUEST = 11
OP_STA_CONNECT_REGISTERED_AP_REQUEST = 12

# InstallationSettingOperationSystem.proto (DriveRec, FW 7.000010)。
# APK lc/b.java:604-626 は Function 1793 (=0x0701) と request/response の対応を持つ。
FUNC_INSTALLATION_SETTING = 0x0701
OP_INSTALLATION_STATUS_REQUEST = 1
OP_INSTALLATION_STATUS_RESPONSE = 0x8001
OP_INSTALLATION_START_REQUEST = 2
OP_INSTALLATION_START_RESPONSE = 0x8002
OP_INSTALLATION_CANCEL_NOTIFY = 3
OP_INSTALLATION_FINISHED_NOTIFY = 4
OP_LIVING_CONFIRMATION_REQUEST = 6
OP_LIVING_CONFIRMATION_RESPONSE = 0x8006
OP_VIDEO_STREAMING_NOTIFY = 0x8007
OP_SWITCH_VIDEO_STREAMING_REQUEST = 11
OP_SWITCH_VIDEO_STREAMING_RESPONSE = 0x800B
OP_LOCAL_AP_SETTING_REQUEST = 12
OP_LOCAL_AP_SETTING_RESPONSE = 0x800C

INSTALLATION_CAMERAS = {"front": 1, "in": 2}
INSTALLATION_BANDS = {0: "DEFAULT", 1: "2.4GHz", 2: "5GHz"}

STA_RESULTS = {0: "DEFAULT", 1: "SUCCESS", 2: "ERROR"}
STA_ERRORS = {
    0: "DEFAULT",
    1: "NONE",
    2: "UNKNOWN",
    3: "STA_SETTING (STA が OFF)",
    4: "SSID",
    5: "SECURITY_TYPE",
    6: "PASSWORD",
}
STA_SETTINGS = {0: "DEFAULT", 1: "ON", 2: "OFF"}
STA_SECURITIES = {0: "DEFAULT", 1: "OPEN", 2: "WPA1/WPA2", 3: "WPA2/WPA3"}
STA_AUTO_CONNECTS = {0: "DEFAULT", 1: "AUTO", 2: "OFF"}
STA_STRENGTHS = {
    0: "DEFAULT",
    1: "NONE",
    2: "LEVEL1",
    3: "LEVEL2",
    4: "LEVEL3",
    5: "LEVEL4",
    6: "LEVEL5",
}
STA_CONNECTED = {0: "DEFAULT", 1: "CONNECTED", 2: "NOT_CONNECTED"}
# CLI から受け取る名前 -> SecurityType。WPA2 パーソナルの AP は wpa1-wpa2。
STA_SECURITY_INPUT = {"open": 1, "wpa1-wpa2": 2, "wpa2-wpa3": 3}

# CDBG_SRV_DBG_AppCooperation::OnKeyEvent が照合する 6 キー列
# (System .rodata 0x19E070、int32 x6)
KEY_SEQUENCE = (2, 1, 2, 1, 1, 2)
# OnMaintenanceEntryExitStartNotify の NTimer::Restart(60000)
FIRMWARE_KEY_TIMEOUT_SECONDS = 60.0


class Np1Error(RuntimeError):
    """処理を継続できない場合の例外。"""


VERBOSE = False


# serve 中は、コマンド1件分の出力をここへ溜めて呼び出し元へ返す。
_LOG_SINK: list[str] | None = None


def log(message: str) -> None:
    if _LOG_SINK is not None:
        _LOG_SINK.append(message)
        return
    print(message, flush=True)


def debug(message: str) -> None:
    if VERBOSE:
        print(message, flush=True)


# --------------------------------------------------------------------------
# protobuf (必要最小限の手組み)
# --------------------------------------------------------------------------


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative varintは未対応です")
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data):
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if current & 0x80 == 0:
            return value, offset
        shift += 7
        if shift >= 64:
            raise Np1Error("protobuf varintが64bitを超えています")
    raise Np1Error("protobuf varintが途中で終了しました")


def protobuf_string(field_number: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return encode_varint((field_number << 3) | 2) + encode_varint(len(encoded)) + encoded


def protobuf_int(field_number: int, value: int) -> bytes:
    return encode_varint(field_number << 3) + encode_varint(value)


def protobuf_bool(field_number: int, value: bool) -> bytes:
    """proto3 は false を省略するが、意図が wire 上に残るよう明示的に出す。"""
    return encode_varint(field_number << 3) + encode_varint(1 if value else 0)


def parse_protobuf(data: bytes) -> dict[int, Any]:
    fields: dict[int, Any] = {}
    offset = 0
    while offset < len(data):
        key, offset = decode_varint(data, offset)
        field_number = key >> 3
        wire_type = key & 7
        if field_number == 0:
            raise Np1Error("protobuf field number 0を受信しました")
        if wire_type == 0:
            value, offset = decode_varint(data, offset)
        elif wire_type == 1:
            value, offset = data[offset : offset + 8], offset + 8
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            value, offset = data[offset : offset + length], offset + length
        elif wire_type == 5:
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise Np1Error(f"未対応のprotobuf wire typeです: {wire_type}")
        if offset > len(data):
            raise Np1Error("protobuf値が途中で終了しました")
        # repeated フィールド (登録AP一覧など) は list にまとめる。
        # 先勝ちで捨てると RegisteredApListResponse.apInfo が 1 件しか読めない。
        if field_number not in fields:
            fields[field_number] = value
        elif isinstance(fields[field_number], list):
            fields[field_number].append(value)
        else:
            fields[field_number] = [fields[field_number], value]
    return fields


def protobuf_str_field(fields: dict[int, Any], number: int, name: str) -> str:
    value = fields.get(number)
    if not isinstance(value, bytes):
        raise Np1Error(f"protobuf {name}がbytesではありません")
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Np1Error(f"protobuf {name}がUTF-8ではありません") from error


# --------------------------------------------------------------------------
# PDU (k4/a.java k0() / s0()、ed/i.java m0())
# --------------------------------------------------------------------------


def _body(
    token: bytes, function_id: int, opcode: int, request_id: int, payload: bytes
) -> bytes:
    return (
        token
        + struct.pack(">q", int(time.time()))
        + struct.pack(">HHB", function_id, opcode, request_id & 0xFF)
        + payload
    )


def plain_frame(
    function_id: int, opcode: int, request_id: int, payload: bytes = b""
) -> bytes:
    """frame mode 1 (NORMAL)。token は 0xFF x8、signature は 0xFF x4。"""
    return _body(b"\xff" * 8, function_id, opcode, request_id, payload) + b"\xff" * 4


def signed_frame(
    access_token: str,
    secret: str,
    function_id: int,
    opcode: int,
    request_id: int,
    payload: bytes = b"",
) -> bytes:
    """frame mode 2 (SECURE)。signature = SHA-256(secret || body)[0:4]。"""
    body = _body(access_token.encode(), function_id, opcode, request_id, payload)
    return body + hashlib.sha256(secret.encode() + body).digest()[:4]


def decode_pdu(data: bytes) -> tuple[int, int, int, bytes]:
    """先頭 16 byte は APK も解釈しないので読み飛ばす。"""
    if len(data) < 21:
        raise Np1Error(f"21 byte未満のPDUを受信しました: {data.hex()}")
    function_id, opcode, request_id = struct.unpack(">HHB", data[16:21])
    return function_id, opcode, request_id, data[21:]


def decode_edge_state(data: bytes) -> dict[str, Any]:
    if len(data) < 35:
        raise Np1Error(f"35 byte未満のEdgeSystemStateです: {data.hex()}")
    try:
        device_no = data[19:35].decode()
    except UnicodeDecodeError as error:
        raise Np1Error("DeviceNoがUTF-8ではありません") from error
    return {
        "version_firm": f"{data[4]:x}.{data[5]:02x}{data[6]:02x}{data[7]:02x}",
        "version_platform": str(struct.unpack(">i", data[8:12])[0]),
        "version_boot": f"{data[12]:x}.{data[13]:02x}{data[14]:02x}{data[15]:02x}",
        "startup_mode": data[17],
        "certification": data[18],
        "device_no": device_no,
    }


class RequestIdCounter:
    """hc/a.java i(): 1 始まり、255 以上で 1 へ戻す。応答不要なら 0。"""

    def __init__(self) -> None:
        self._next = 1

    def take(self) -> int:
        current = self._next
        self._next = 1 if current >= 255 else current + 1
        return current


# --------------------------------------------------------------------------
# HTTP (userKey 取得のみ)
# --------------------------------------------------------------------------


def http_login(email: str, password: str, user_agent: str) -> dict[str, Any]:
    body = json.dumps(
        {
            "grantType": "password",
            "id": email,
            "pw": password,
            "manufacturerId": "01",
            "longExpireFlag": "1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        LOGIN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": user_agent,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise Np1Error(f"ログイン失敗: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise Np1Error(f"ログイン通信失敗: {error.reason}") from error

    parsed = json.loads(raw.decode("utf-8"))
    result = parsed.get("results", {}).get("result")
    if not isinstance(result, dict) or not isinstance(result.get("userKey"), str):
        raise Np1Error("ログイン応答にuserKeyがありません")
    expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
        seconds=int(result.get("expiresIn", 0))
    )
    return {
        "access_token": result["accessToken"],
        "token_type": result.get("tokenType", ""),
        "expires_in_seconds": int(result.get("expiresIn", 0)),
        "refresh_token": result.get("refreshToken", ""),
        "user_key": result["userKey"],
        "access_token_expires_at": expires_at.isoformat(),
    }


def http_refresh(refresh_token: str, user_agent: str) -> dict[str, Any]:
    """保存済み refresh token で account access token を取り直す。

    refresh token はローテーションするので、返った値を必ず保存し直すこと。
    """
    body = json.dumps(
        {
            "grantType": "refresh_token",
            "refreshToken": refresh_token,
            "manufacturerId": "01",
            "longExpireFlag": "1",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        LOGIN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": user_agent,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        raise Np1Error(f"token refresh 失敗: HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise Np1Error(f"token refresh 通信失敗: {error.reason}") from error

    result = json.loads(raw.decode("utf-8")).get("results", {}).get("result")
    if not isinstance(result, dict) or not isinstance(result.get("accessToken"), str):
        raise Np1Error("refresh 応答に accessToken がありません")
    expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
        seconds=int(result.get("expiresIn", 0))
    )
    return {
        "access_token": result["accessToken"],
        "token_type": result.get("tokenType", ""),
        "expires_in_seconds": int(result.get("expiresIn", 0)),
        "refresh_token": result.get("refreshToken", ""),
        "user_key": result.get("userKey", ""),
        "access_token_expires_at": expires_at.isoformat(),
    }


def http_token_expired(http: dict[str, Any]) -> bool:
    raw = http.get("access_token_expires_at")
    if not isinstance(raw, str):
        return True
    try:
        expires = dt.datetime.fromisoformat(raw)
    except ValueError:
        return True
    if expires.tzinfo is None:
        return True
    # APK (xc/h.java) と同じく、期限の 5 分前から前倒しで取り直す
    return expires <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)


def get_member_token(
    access_token: str, device_number: str, target: str, user_agent: str
) -> dict[str, str]:
    """POST /token/members/accesstoken。

    `target` は "owner" / "driver"。応答の refreshToken と userKey を
    EdgeInfo LOGIN_REQUEST / CHECK_IN_REQUEST へそのまま渡す
    (np1ctl.py command_setup と同じ)。member token 自体は本体側が使う。
    """
    body = json.dumps(
        {"target": target, "devNum": device_number, "manufacturerId": "01"},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        MEMBER_TOKEN_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": user_agent,
            "Authorization": f"Bearer {access_token}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read()[:400].decode("utf-8", "replace")
        raise Np1Error(f"member token 失敗: HTTP {error.code} {detail}") from error
    except urllib.error.URLError as error:
        raise Np1Error(f"member token 通信失敗: {error.reason}") from error

    result = json.loads(raw.decode("utf-8")).get("results", {}).get("result")
    if not isinstance(result, dict):
        raise Np1Error("member token 応答が不正です")
    for key in ("refreshToken", "userKey"):
        if not isinstance(result.get(key), str) or not result[key]:
            raise Np1Error(f"member token 応答に {key} がありません")
    return {
        "access_token": str(result.get("accessToken", "")),
        "refresh_token": result["refreshToken"],
        "user_key": result["userKey"],
        "last_name_kana": str(result.get("lastNameKana", "") or ""),
        "first_name_kana": str(result.get("firstNameKana", "") or ""),
    }


# --------------------------------------------------------------------------
# session.json (np1_e2e.py と互換。未知フィールドは壊さず read-modify-write)
# --------------------------------------------------------------------------


def load_session(path: Path) -> dict[str, Any]:
    path = path.expanduser()
    if not path.exists():
        return {}
    try:
        with path.open() as file:
            payload = json.load(file)
    except (OSError, json.JSONDecodeError) as error:
        raise Np1Error(f"sessionを読めません: {path}") from error
    return payload if isinstance(payload, dict) else {}


def save_session(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = dict(payload)
    payload["formatVersion"] = 2
    payload["savedAt"] = dt.datetime.now(dt.timezone.utc).isoformat()
    temporary = path.with_name(f".{path.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def client_model() -> str:
    """APK の Build.MODEL 相当。"""
    return platform.machine().strip() or "python-np1"


# --------------------------------------------------------------------------
# BLE トランスポート
# --------------------------------------------------------------------------


class Np1Link:
    """1 本の GATT 接続に対する PDU 送受信。"""

    def __init__(self, transport) -> None:
        self.transport = transport
        self.data_queue = transport.data_queue
        self.access_token = ""
        self.secret = ""
        self.control_point = SECURE_CONTROL_POINT
        self._normal_credentials: tuple[str, str] | None = None
        self._counters: dict[int, RequestIdCounter] = {}

    # -- notify ------------------------------------------------------------

    async def subscribe(self) -> None:
        """ed/c.java と同じ順序で notify を有効化する。"""
        await self.transport.subscribe_all()
        debug("[*] notify 設定完了 (5 characteristic)")

    async def read_edge_state(self) -> dict[str, Any]:
        return decode_edge_state(await self.transport.read(EDGE_SYSTEM_STATE))

    # -- write -------------------------------------------------------------

    async def _write(self, characteristic: str, frame_factory: Callable[[], bytes]) -> None:
        last_error: BaseException | None = None
        for attempt in range(1, WRITE_ATTEMPTS + 1):
            try:
                await asyncio.wait_for(
                    self.transport.write(characteristic, frame_factory()),
                    timeout=WRITE_ACK_TIMEOUT_SECONDS,
                )
                debug(f"[*] write ACK ({attempt}/{WRITE_ATTEMPTS})")
                return
            except (TimeoutError, asyncio.TimeoutError, OSError, TransportError) as error:
                last_error = error
                log(f"[*] write ACKなし ({attempt}/{WRITE_ATTEMPTS}): {error}")
        raise Np1Error(
            f"{WRITE_ATTEMPTS}回のwrite後もACKがありません (RETRY_OVER)"
        ) from last_error

    def _next_request_id(self, function_id: int, expect_response: bool) -> int:
        if not expect_response:
            return 0
        counter = self._counters.setdefault(function_id, RequestIdCounter())
        return counter.take()

    async def send_plain(
        self, function_id: int, opcode: int, payload: bytes = b"", request_id: int = 1
    ) -> None:
        """frame mode 1 を Secure ControlPoint へ書く (通常ペアリングの Opcode 2)。"""
        log(f"[>] plain  function=0x{function_id:04x} opcode={opcode} reqId={request_id}")
        await self._write(
            SECURE_CONTROL_POINT,
            lambda: plain_frame(function_id, opcode, request_id, payload),
        )

    async def send(
        self,
        function_id: int,
        opcode: int,
        payload: bytes = b"",
        *,
        expect_response: bool = True,
        redact: bool = False,
        request_id: int | None = None,
        characteristic: str | None = None,
    ) -> int:
        """redact=True の payload は hex を伏せる。

        Wi-Fi の PSK や member token の refresh token は、そのまま出すと
        serve.log と call の応答に平文で残ってしまう。
        """
        if not self.access_token or not self.secret:
            raise Np1Error("access token / secret が未設定です")
        request_id = (
            self._next_request_id(function_id, expect_response)
            if request_id is None
            else request_id
        )
        shown = (
            f"<{len(payload)} bytes 非表示>"
            if redact and payload
            else (payload.hex() or "(empty)")
        )
        log(
            f"[>] signed function=0x{function_id:04x} opcode={opcode} "
            f"reqId={request_id} payload={shown}"
        )
        await self._write(
            characteristic or self.control_point,
            lambda: signed_frame(
                self.access_token,
                self.secret,
                function_id,
                opcode,
                request_id,
                payload,
            ),
        )
        return request_id

    # -- read --------------------------------------------------------------

    async def next_pdu(
        self, timeout: float, *, redact: bool = False
    ) -> tuple[str, int, int, int, bytes]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Np1Error("PDU待ちがtimeoutしました")
            try:
                source, raw = await asyncio.wait_for(
                    self.data_queue.get(), timeout=remaining
                )
            except (TimeoutError, asyncio.TimeoutError) as error:
                raise Np1Error("PDU待ちがtimeoutしました") from error
            if source == EDGE_SYSTEM_STATE:
                debug(f"[*] ESS notify {raw.hex()}")
                continue
            function_id, opcode, request_id, payload = decode_pdu(raw)
            shown = (
                f"<{len(payload)} bytes 非表示>"
                if redact and payload
                else (payload.hex() or "(empty)")
            )
            log(
                f"[<] {_source_name(source)} function=0x{function_id:04x} "
                f"opcode=0x{opcode:04x} reqId={request_id} "
                f"payload={shown}"
            )
            return source, function_id, opcode, request_id, payload

    async def expect(
        self,
        function_id: int,
        opcode: int,
        timeout: float,
        request_id: int | None = None,
        *,
        redact: bool = False,
    ) -> bytes:
        while True:
            _source, got_function, got_opcode, got_request, payload = (
                await self.next_pdu(timeout, redact=redact)
            )
            raise_if_ble_error(got_function, got_opcode, payload)
            if got_function != function_id or got_opcode != opcode:
                debug("[*] 対象外のPDUを読み飛ばします")
                continue
            if request_id not in (None, 0) and got_request != request_id:
                log(
                    f"[!] requestId不一致 (期待 {request_id} / 受信 {got_request})。"
                    "そのまま採用します"
                )
            return payload


def _source_name(source: str) -> str:
    return {
        DATA_SOURCE: "DataSource",
        NOTIFICATION_SOURCE: "NotifySource",
        SECURE_DATA_SOURCE: "SecureDataSource",
        SECURE_NOTIFICATION_SOURCE: "SecureNotifySource",
    }.get(source, source)


def raise_if_ble_error(function_id: int, opcode: int, payload: bytes) -> None:
    if function_id != 0 or opcode != 0x8001:
        return
    number = parse_protobuf(payload).get(1, 0)
    name = BLE_ERRORS.get(number if isinstance(number, int) else -1, "UNRECOGNIZED")
    raise Np1Error(f"NP1認証エラー: {number} ({name})")


# --------------------------------------------------------------------------
# スキャン・接続
# --------------------------------------------------------------------------

# BlueZ は BR/EDR へ繋ぎに行って org.bluez.Error.NotAvailable を返すことがある。
# 再試行で拾えるよう bleak の例外も retry 対象に入れる。
GATT_ERRORS = (
    TimeoutError,
    asyncio.TimeoutError,
    TransportError,
    OSError,
) + gatt_error_types()


async def scan_device(transport, device_name, address, timeout: float):
    """NP1 service UUID で絞って 1 台見つける。"""
    found = await transport.scan(timeout, address=address, name=device_name)
    if not found:
        raise Np1Error(
            f"NP1 ({address or device_name or 'any'}) を検出できませんでした"
        )
    return found[0]


async def wait_for_pairing_mode(transport, device_name, timeout: float):
    """StartupMode==0 (NORMAL) かつ Certification!=0 (ACCEPTING) を待つ。"""
    deadline = None if timeout <= 0 else time.monotonic() + timeout
    while deadline is None or time.monotonic() < deadline:
        remaining = 20.0 if deadline is None else max(2.0, deadline - time.monotonic())
        try:
            device = await scan_device(transport, device_name, None, min(20.0, remaining))
        except Np1Error as error:
            log(f"[*] スキャン継続: {error}")
            continue
        try:
            await transport.connect(device)
            await asyncio.sleep(POST_CONNECT_DELAY_SECONDS)
            while deadline is None or time.monotonic() < deadline:
                state = decode_edge_state(await transport.read(EDGE_SYSTEM_STATE))
                log(
                    "[*] EdgeSystemState "
                    f"StartupMode={state['startup_mode']} "
                    f"Certification={state['certification']} "
                    f"firm={state['version_firm']} no={state['device_no']}"
                )
                if state["startup_mode"] == 0 and state["certification"] != 0:
                    await transport.disconnect()
                    return state, device
                await asyncio.sleep(1.0)
        except GATT_ERRORS as error:
            log(f"[*] GATT 再試行: {type(error).__name__}: {error}")
        finally:
            with suppress(Exception):
                await transport.disconnect()
        await asyncio.sleep(1.0)
    raise Np1Error("NORMAL / ACCEPTINGの待機時間を超えました")


@asynccontextmanager
async def connect_with_retry(
    transport,
    device_name,
    address,
    scan_timeout: float,
    gatt_timeout: float,
    total_timeout: float,
    pair: bool = False,
):
    """スキャンと GATT 接続を成功するまで繰り返す。

    NP1 は切断直後しばらく接続を受け付けないことがある。BlueZ は
    BR/EDR 側へ繋ぎに行って org.bluez.Error.NotAvailable を返すこともある
    (NP1 は Serial Port プロファイルも持つ dual-mode 機器)。
    どちらも再試行で拾う。
    """
    deadline = None if total_timeout <= 0 else time.monotonic() + total_timeout
    attempt = 0
    while deadline is None or time.monotonic() < deadline:
        attempt += 1
        remaining = scan_timeout if deadline is None else max(
            2.0, min(scan_timeout, deadline - time.monotonic())
        )
        try:
            device = await scan_device(transport, device_name, address, remaining)
        except Np1Error as error:
            log(f"[*] スキャン再試行 ({attempt}): {error}")
            continue

        log(
            f"[+] {device.address} (rssi={device.rssi}) を検出。"
            f"GATT 接続します ({attempt} 回目)"
        )
        link = Np1Link(transport)
        try:
            await transport.connect(device, pair=pair)
            await asyncio.sleep(POST_CONNECT_DELAY_SECONDS)
            await link.subscribe()
        except GATT_ERRORS as error:
            log(f"[*] GATT 再試行 ({attempt}): {type(error).__name__}: {error}")
            with suppress(Exception):
                await transport.disconnect()
            await asyncio.sleep(1.5)
            continue

        try:
            yield link, device
        finally:
            with suppress(Exception):
                await transport.disconnect()
        return
    raise Np1Error(
        "GATT 接続の待機時間を超えました。"
        "NP1 の電源と、他のアプリが繋いでいないかを確認してください"
    )


# --------------------------------------------------------------------------
# 認証 (Opcode 2 / 3 / 4 / 8 / 10)
# --------------------------------------------------------------------------


async def issue_tokens(link: Np1Link, model: str, timeout: float) -> dict[str, str]:
    """Opcode 2: frame mode 1 を Secure ControlPoint へ書いて token を発行させる。"""
    await link.send_plain(0, 2, protobuf_string(1, model), request_id=1)
    payload = await link.expect(0, 0x8002, timeout, redact=True)
    fields = parse_protobuf(payload)
    tokens = {
        "access_token": protobuf_str_field(fields, 1, "accessToken"),
        "refresh_token": protobuf_str_field(fields, 2, "refreshToken"),
        "secret": protobuf_str_field(fields, 3, "secret"),
    }
    if not all(tokens.values()):
        raise Np1Error("BLE認証情報に空文字列があります")
    log("[+] Opcode 2: BLE access/refresh token と secret を取得")
    return tokens


async def challenge(link: Np1Link, model: str, refresh_token: str, timeout: float) -> dict[str, str] | None:
    """Opcode 3。ACCESS_TOKEN_EXPIRED なら Opcode 4 で更新する。"""
    await link.send(0, 3, protobuf_string(1, model))
    while True:
        _source, function_id, opcode, got_request, payload = await link.next_pdu(timeout)
        if function_id != 0:
            continue
        if opcode == 0x8003:
            log("[+] Opcode 3: challenge 成功")
            return None
        if opcode == 0x8001:
            number = parse_protobuf(payload).get(1, 0)
            if number != 1:
                raise_if_ble_error(function_id, opcode, payload)
            log("[*] ACCESS_TOKEN_EXPIRED。Opcode 4 で更新します")
            await link.send(0, 4, protobuf_string(1, refresh_token))
            refreshed = parse_protobuf(
                await link.expect(0, 0x8004, timeout, redact=True)
            )
            updated = {
                "access_token": protobuf_str_field(refreshed, 1, "accessToken"),
                "refresh_token": protobuf_str_field(refreshed, 2, "refreshToken"),
            }
            link.access_token = updated["access_token"]
            log("[+] Opcode 4: BLE token を更新")
            return updated
        debug(f"[*] challenge 中に想定外のopcode 0x{opcode:04x} (reqId={got_request})")


async def activate_user_key(link: Np1Link, user_key: str, timeout: float) -> str | None:
    """Opcode 8 → Opcode 10。APK の state 11 → 12 → 16 相当。"""
    await link.send(0, 8, protobuf_string(1, user_key), redact=True)
    active_user_key: str | None = None
    try:
        _source, function_id, opcode, _request_id, payload = await link.next_pdu(timeout)
        if function_id == 0 and opcode in (0x8008, 0x8009):
            active_user_key = protobuf_str_field(
                parse_protobuf(payload), 1, "activeUserKey"
            )
            log("[+] Opcode 8: activeUserKey を取得")
        elif function_id == 0 and opcode == 0x8001:
            number = parse_protobuf(payload).get(1, 0)
            log(
                f"[!] Opcode 8 error={number} "
                f"({BLE_ERRORS.get(number, 'UNRECOGNIZED')}) - 続行します"
            )
    except Np1Error as error:
        log(f"[!] Opcode 8 応答なし: {error} - 続行します")

    await link.send(0, 10, b"")
    with suppress(Np1Error):
        await link.next_pdu(timeout)
    log("[+] Opcode 10: INIT_COMPLETE 相当まで完了")
    return active_user_key


# --------------------------------------------------------------------------
# ペアリング後の無音化と初期設定完了 (Function 0x0400 / 0x0200)
# --------------------------------------------------------------------------


async def volume_setting_status(link: Np1Link, timeout: float) -> dict[str, int]:
    """0x0400/1 で master volume・mute・補正を読む。"""
    request_id = await link.send(
        FUNC_VOLUME_SETTING, OP_VOLUME_SETTING_REQUEST, b""
    )
    response = await link.expect(
        FUNC_VOLUME_SETTING,
        OP_VOLUME_SETTING_RESPONSE,
        timeout,
        request_id,
    )
    fields = parse_protobuf(response)
    status = {
        "volume": int_or_zero(fields, 1),
        "mute": int_or_zero(fields, 2),
        "correction": int_or_zero(fields, 3),
    }
    log(
        "[+] VolumeSetting: "
        f"volume={status['volume']} "
        f"mute={status['mute']} "
        f"({COMMON_ON_OFF.get(status['mute'], 'UNRECOGNIZED')}) "
        f"correction={status['correction']}"
    )
    return status


async def set_mute(link: Np1Link, enabled: bool, timeout: float) -> dict[str, int]:
    """0x0400/3 MuteRequest を送り、0x0400/1 の読み返しまで行う。

    FW 7.000010 Setting の OnVolumeSettingMuteNotify
    (0x08eb68..0x08ed10) は CommonOnOff だけを受け付け、COMMON_ON (2) を
    AL_SRV_SET_ID_MUTE の内部値 0、COMMON_OFF (1) を内部値 1 へ変換する。
    """
    requested = COMMON_ON if enabled else COMMON_OFF
    request_id = await link.send(
        FUNC_VOLUME_SETTING,
        OP_MUTE_REQUEST,
        protobuf_int(1, requested),
    )
    response = await link.expect(
        FUNC_VOLUME_SETTING, OP_MUTE_RESPONSE, timeout, request_id
    )
    result = bool(int_or_zero(parse_protobuf(response), 1))
    if not result:
        raise Np1Error(
            f"MuteResponse が失敗を返しました (requested={requested})"
        )
    status = await volume_setting_status(link, timeout)
    if status["mute"] != requested:
        raise Np1Error(
            "MuteRequest 後の読み返しが一致しません: "
            f"requested={requested} actual={status['mute']}"
        )
    log(f"[+] mute を {'ON' if enabled else 'OFF'} に設定し、読み返しで確認しました")
    return status


async def set_master_volume(
    link: Np1Link, volume: int, timeout: float
) -> dict[str, int]:
    """0x0400/2 でmaster volumeを設定し、0x0400/1で確認する。"""
    if not 0 <= volume <= 10:
        raise Np1Error("master volume は 0..10 です")
    request_id = await link.send(
        FUNC_VOLUME_SETTING,
        OP_MASTER_VOLUME_REQUEST,
        protobuf_int(1, volume),
    )
    response = await link.expect(
        FUNC_VOLUME_SETTING,
        OP_MASTER_VOLUME_RESPONSE,
        timeout,
        request_id,
    )
    result = bool(int_or_zero(parse_protobuf(response), 1))
    if not result:
        raise Np1Error(f"MasterVolumeResponse が失敗を返しました (volume={volume})")
    status = await volume_setting_status(link, timeout)
    if status["volume"] != volume:
        raise Np1Error(
            "MasterVolumeRequest 後の読み返しが一致しません: "
            f"requested={volume} actual={status['volume']}"
        )
    log(f"[+] master volume={volume} を読み返しで確認しました")
    return status


async def initial_setup_status(link: Np1Link, timeout: float) -> int:
    """0x0200/1 で InitialSetupFinishStatus を読む。"""
    request_id = await link.send(
        FUNC_INITIAL_SETUP, OP_INITIAL_SETUP_STATUS_REQUEST, b""
    )
    response = await link.expect(
        FUNC_INITIAL_SETUP,
        OP_INITIAL_SETUP_STATUS_RESPONSE,
        timeout,
        request_id,
    )
    status = int_or_zero(parse_protobuf(response), 1)
    log(
        f"[+] InitialSetupFinishStatus = {status} "
        f"({INITIAL_SETUP_STATUSES.get(status, 'UNRECOGNIZED')})"
    )
    return status


async def ensure_initial_setup_finished(link: Np1Link, timeout: float) -> bool:
    """必要なら 0x0200/2 status=FINISHED を送り、0x0200/1 で確認する。

    戻り値は、この呼び出しが FinishedNotify を送ったかどうか。
    """
    before = await initial_setup_status(link, timeout)
    if before == INITIAL_SETUP_FINISHED:
        return False
    if before not in (
        INITIAL_SETUP_FINISHED_EXCEPT_COMMUNICATION,
        INITIAL_SETUP_NOT_FINISHED,
    ):
        raise Np1Error(f"未知の InitialSetupFinishStatus です: {before}")

    await link.send(
        FUNC_INITIAL_SETUP,
        OP_INITIAL_SETUP_FINISHED_NOTIFY,
        protobuf_int(1, INITIAL_SETUP_FINISHED),
        expect_response=False,
    )
    log("[+] 0x0200/2 INITIAL_SETUP_FINISHED_NOTIFY status=1 を送信")

    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Np1Error(
                "InitialSetupFinishStatus が FINISHED になる前に timeout しました"
            )
        after = await initial_setup_status(link, remaining)
        if after == INITIAL_SETUP_FINISHED:
            log("[+] InitialSetupFinishStatus=FINISHED を読み返しで確認しました")
            return True
        await asyncio.sleep(min(0.5, remaining))


async def enforce_silent_audio(
    link: Np1Link,
    timeout: float,
    *,
    force_mute_request: bool,
) -> dict[str, Any]:
    """mute ONとmaster volume 0を読み返しまで含めて確定する。"""
    mute_request_sent = False
    if force_mute_request:
        status = await set_mute(link, True, timeout)
        mute_request_sent = True
    else:
        status = await volume_setting_status(link, timeout)
        if status["mute"] != COMMON_ON:
            status = await set_mute(link, True, timeout)
            mute_request_sent = True
    volume_request_sent = False
    if status["volume"] != 0:
        status = await set_master_volume(link, 0, timeout)
        volume_request_sent = True
    return {
        **status,
        "mute_request_sent": mute_request_sent,
        "volume_request_sent": volume_request_sent,
    }


async def enforce_silent_initial_setup(
    link: Np1Link,
    timeout: float,
    *,
    force_mute_request: bool,
) -> dict[str, Any]:
    """mute/volumeを先に確定し、その後で初期設定完了を確定する。

    初期値 0 からの InitialSetupFinishedNotify は本体の
    RequestInitialSetupFinishOutput を呼ぶため、先に mute を適用する。
    """
    status = await enforce_silent_audio(
        link, timeout, force_mute_request=force_mute_request
    )
    setup_changed = await ensure_initial_setup_finished(link, timeout)
    return {
        **status,
        "initial_setup_status": INITIAL_SETUP_FINISHED,
        "initial_setup_notify_sent": setup_changed,
    }


async def wait_for_pair_persistence_window(link: Np1Link) -> None:
    """FW の次回 credential 保存周期を跨ぐまで接続を維持する。

    SaveCredential は非同期 task で、BLE 応答として完了通知されない。この待機は
    60,000 ms の周期 timer を必ず一度跨ぐためのもの。再起動後の実ファイル読込は
    次回接続時に別途確認する。
    """
    log(
        "[*] 本体の BLE 資格情報保存周期を跨ぐため、接続を維持します: "
        f"{PAIR_PERSISTENCE_WAIT_SECONDS:.0f} 秒 "
        f"(FW timer {CREDENTIAL_SAVE_INTERVAL_SECONDS:.0f} 秒 + "
        f"猶予 {PERSISTENCE_SCHEDULING_GRACE_SECONDS:.0f} 秒)"
    )
    deadline = time.monotonic() + PAIR_PERSISTENCE_WAIT_SECONDS
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(10.0, remaining))
        if time.monotonic() < deadline:
            await link.read_edge_state()
    log("[+] credential 保存 timer の 1 周期を跨ぎました")


async def wait_for_setting_persistence_window() -> None:
    """Setting.DAT の 3,000 ms debounce と task 起動を跨ぐ。"""
    log(
        "[*] Setting.DAT の保存 debounce を跨ぐため "
        f"{SETTING_SAVE_WAIT_SECONDS:.0f} 秒待ちます"
    )
    await asyncio.sleep(SETTING_SAVE_WAIT_SECONDS)


# --------------------------------------------------------------------------
# Maintenance Mode (Function 0xE000)
# --------------------------------------------------------------------------


def describe_mode(value: int) -> str:
    return f"{value} ({MAINTENANCE_MODES.get(value, 'UNRECOGNIZED')})"


def _key_hint() -> str:
    sequence = ", ".join(str(code) for code in KEY_SEQUENCE)
    return (
        f"NP1本体の音量ボタンを keyCode [{sequence}] の順に 6 回押してください。\n"
        "        実機確認済みの対応は keyCode 2=音量+、1=音量- です:\n"
        "          + - + - - +\n"
        f"        本体側のタイムアウトは {FIRMWARE_KEY_TIMEOUT_SECONDS:.0f} 秒です。"
    )


async def maintenance_enter(
    link: Np1Link,
    password: str,
    key_timeout: float,
    response_timeout: float,
    skip_start: bool = False,
) -> int:
    """StartNotify → キー列待ち → PasswordVerificationRequest。返り値は許可モード。"""
    # FW7 Setting の音量キーhandlerは、mute中の最初の+/-でmuteをOFFにする
    # (0x839a4..0x839c0 / 0x83a74..0x83a90)。先に保存volumeも0にして、
    # キー列一致後・password送信前に必ずmute/volumeを戻す。
    await enforce_silent_audio(link, response_timeout, force_mute_request=False)
    if not skip_start:
        # Opcode 1 はファーム側が応答を返さない (OnMaintenanceEntryExitStartNotify)
        await link.send(
            FUNC_MAINTENANCE, OP_ENTRY_START_NOTIFY, b"", expect_response=False
        )
        log("[+] 0xE000/1 MAINTENANCE_ENTRY_EXIT_START_NOTIFY を送信")

    log("")
    log("  ==> " + _key_hint())
    log("")
    log(f"[*] 0xE000/0x8002 COMMAND_INPUT_END_NOTIFY を待機中 (最大 {key_timeout:.0f} 秒)")

    deadline = time.monotonic() + key_timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Np1Error(
                "キー列の一致通知 (0x8002) が来ませんでした。"
                "押し順・押す速さ・本体60秒タイムアウトを確認してください"
            )
        _source, function_id, opcode, _request_id, payload = await link.next_pdu(remaining)
        raise_if_ble_error(function_id, opcode, payload)
        if function_id == FUNC_MAINTENANCE and opcode == OP_COMMAND_INPUT_END_NOTIFY:
            log("[+] キー列一致 (command correct)。パスワード入力段階へ進みます")
            break
        debug("[*] 対象外のPDUを読み飛ばします")

    await enforce_silent_audio(link, response_timeout, force_mute_request=False)
    request_id = await link.send(
        FUNC_MAINTENANCE,
        OP_PASSWORD_VERIFICATION_REQUEST,
        protobuf_string(1, password),
    )
    log("[+] 0xE000/4 PASSWORD_VERIFICATION_REQUEST を送信")

    payload = await link.expect(
        FUNC_MAINTENANCE,
        OP_PASSWORD_VERIFICATION_RESPONSE,
        response_timeout,
        request_id,
    )
    mode = parse_protobuf(payload).get(1, 0)
    if not isinstance(mode, int):
        raise Np1Error("PasswordVerificationResponse.mode がvarintではありません")
    await enforce_silent_audio(link, response_timeout, force_mute_request=False)
    return mode


async def maintenance_query_mode(link: Np1Link, response_timeout: float) -> int:
    request_id = await link.send(
        FUNC_MAINTENANCE, OP_MAINTENANCE_MODE_REQUEST, b""
    )
    payload = await link.expect(
        FUNC_MAINTENANCE, OP_MAINTENANCE_MODE_RESPONSE, response_timeout, request_id
    )
    mode = parse_protobuf(payload).get(1, 0)
    if not isinstance(mode, int):
        raise Np1Error("MaintenanceModeResponse.mode がvarintではありません")
    return mode


async def maintenance_exit(link: Np1Link) -> None:
    await link.send(FUNC_MAINTENANCE, OP_ENTRY_END_NOTIFY, b"", expect_response=False)
    log("[+] 0xE000/3 MAINTENANCE_ENTRY_EXIT_END_NOTIFY を送信")


# --------------------------------------------------------------------------
# DebugSerialPortIO (Function 0xF00D)
# --------------------------------------------------------------------------


async def serial_get_status(link: Np1Link, timeout: float) -> dict[str, bool]:
    request_id = await link.send(FUNC_SERIAL_PORT_IO, OP_SERIAL_GET_REQUEST, b"")
    payload = await link.expect(
        FUNC_SERIAL_PORT_IO, OP_SERIAL_GET_RESPONSE, timeout, request_id
    )
    fields = parse_protobuf(payload)
    return {
        "result": bool(fields.get(1, 0)),
        "output_status": bool(fields.get(2, 0)),
        "input_status": bool(fields.get(3, 0)),
    }


async def serial_switch(
    link: Np1Link, opcode: int, response_opcode: int, status: bool, timeout: float
) -> bool:
    request_id = await link.send(
        FUNC_SERIAL_PORT_IO, opcode, protobuf_bool(1, status)
    )
    payload = await link.expect(
        FUNC_SERIAL_PORT_IO, response_opcode, timeout, request_id
    )
    return bool(parse_protobuf(payload).get(1, 0))


# --------------------------------------------------------------------------
# Function 0x0500: 外部 Wi-Fi (STA)
# --------------------------------------------------------------------------


def enum_name(table: dict[int, str], value: Any) -> str:
    if not isinstance(value, int):
        return "UNRECOGNIZED"
    return f"{value} ({table.get(value, 'UNRECOGNIZED')})"


def int_or_zero(fields: dict[int, Any], number: int) -> int:
    value = fields.get(number, 0)
    return value if isinstance(value, int) else 0


def repeated(fields: dict[int, Any], number: int) -> list[Any]:
    value = fields.get(number)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def security_type(name: str) -> int:
    if name not in STA_SECURITY_INPUT:
        raise Np1Error(
            f"securityType は {'/'.join(sorted(STA_SECURITY_INPUT))} のどれかです: {name}"
        )
    return STA_SECURITY_INPUT[name]


def validate_sta_ssid(ssid: str) -> None:
    """SSID は ASCII 表示可能文字 1..32 文字 (APK の入力チェックと同じ)。"""
    if not 1 <= len(ssid) <= 32:
        raise Np1Error("SSID は 1..32 文字です")
    if not all(0x20 <= ord(character) <= 0x7E for character in ssid):
        raise Np1Error("SSID は ASCII U+0020..U+007E のみです")


def validate_sta_password(security: int, password: str) -> None:
    if security == 1:
        if password:
            raise Np1Error("open network の password は空である必要があります")
        return
    if not 8 <= len(password) <= 128:
        raise Np1Error("password は 8..128 文字です")
    if not all(0x20 <= ord(character) <= 0x7E for character in password):
        raise Np1Error("password は ASCII U+0020..U+007E のみです")


async def sta_request(
    link: Np1Link, opcode: int, payload: bytes, timeout: float
) -> dict[int, Any]:
    request_id = await link.send(FUNC_WIFI_STA, opcode, payload)
    response = await link.expect(
        FUNC_WIFI_STA, opcode | 0x8000, timeout, request_id
    )
    return parse_protobuf(response)


def log_result_error(fields: dict[int, Any]) -> bool:
    result = int_or_zero(fields, 1)
    log(f"    result = {enum_name(STA_RESULTS, result)}")
    log(f"    error  = {enum_name(STA_ERRORS, int_or_zero(fields, 2))}")
    return result == 1


async def sta_info(link: Np1Link, timeout: float) -> dict[int, Any]:
    """0x0500/1 StaSettingInformationRequest。STA の ON/OFF と IP を読む。"""
    fields = await sta_request(link, OP_STA_INFO_REQUEST, b"", timeout)
    log("[+] 0x0500/0x8001 StaSettingInformationResponse")
    log_result_error(fields)
    log(f"    setting            = {enum_name(STA_SETTINGS, int_or_zero(fields, 3))}")
    log(f"    macAddress         = {protobuf_str_field_or_default(fields, 4)!r}")
    log(f"    ipAddress          = {protobuf_str_field_or_default(fields, 5)!r}")
    log(f"    registeredApMaxNum = {int_or_zero(fields, 6)}")
    return fields


async def sta_set_enabled(link: Np1Link, enabled: bool, timeout: float) -> bool:
    """0x0500/2 StaSettingChangeRequest。接続前に ON にしておく必要がある。"""
    fields = await sta_request(
        link,
        OP_STA_SETTING_CHANGE_REQUEST,
        protobuf_int(1, 1 if enabled else 2),
        timeout,
    )
    log(f"[+] 0x0500/0x8002 StaSettingChangeResponse (要求: {'ON' if enabled else 'OFF'})")
    ok = log_result_error(fields)
    log(f"    setting = {enum_name(STA_SETTINGS, int_or_zero(fields, 3))}")
    return ok


async def sta_nearby(link: Np1Link, page: int, timeout: float) -> dict[int, Any]:
    """0x0500/5 NearbyApListRequest。本体が見つけている AP を列挙する。

    1 応答あたり 5 件。num はページ番号で 1 始まり。
    """
    fields = await sta_request(
        link, OP_STA_NEARBY_AP_LIST_REQUEST, protobuf_int(1, page), timeout
    )
    log(f"[+] 0x0500/0x8005 NearbyApListResponse (page={page})")
    log_result_error(fields)
    log(f"    responseNum = {int_or_zero(fields, 3)} / allNum = {int_or_zero(fields, 4)}")
    for encoded in repeated(fields, 5):
        if not isinstance(encoded, bytes):
            continue
        item = parse_protobuf(encoded)
        log(
            f"    - ssid={protobuf_str_field_or_default(item, 1)!r} "
            f"security={enum_name(STA_SECURITIES, int_or_zero(item, 2))} "
            f"strength={enum_name(STA_STRENGTHS, int_or_zero(item, 3))}"
        )
    return fields


async def sta_registered(link: Np1Link, page: int, timeout: float) -> dict[int, Any]:
    """0x0500/4 RegisteredApListRequest。本体に保存済みの AP を列挙する。"""
    fields = await sta_request(
        link, OP_STA_REGISTERED_AP_LIST_REQUEST, protobuf_int(1, page), timeout
    )
    log(f"[+] 0x0500/0x8004 RegisteredApListResponse (page={page})")
    log_result_error(fields)
    log(f"    responseNum = {int_or_zero(fields, 3)} / allNum = {int_or_zero(fields, 4)}")
    for encoded in repeated(fields, 5):
        if not isinstance(encoded, bytes):
            continue
        item = parse_protobuf(encoded)
        log(
            f"    - ssid={protobuf_str_field_or_default(item, 1)!r} "
            f"autoCon={enum_name(STA_AUTO_CONNECTS, int_or_zero(item, 2))} "
            f"security={enum_name(STA_SECURITIES, int_or_zero(item, 3))} "
            f"strength={enum_name(STA_STRENGTHS, int_or_zero(item, 4))} "
            f"status={enum_name(STA_CONNECTED, int_or_zero(item, 5))}"
        )
    return fields


async def sta_connecting_ap(link: Np1Link, timeout: float) -> dict[int, Any]:
    """0x0500/6 DuringConnectionApInformationRequest。今どこに繋いでいるか。"""
    fields = await sta_request(link, OP_STA_CONNECTING_AP_REQUEST, b"", timeout)
    log("[+] 0x0500/0x8006 DuringConnectionApInformationResponse")
    log_result_error(fields)
    log(f"    connectingAp = {bool(int_or_zero(fields, 3))}")
    log(f"    ssid         = {protobuf_str_field_or_default(fields, 4)!r}")
    return fields


def sta_connect_payload(ssid: str, security: int, password: str) -> bytes:
    """ApConnectRequest{ ssid=1, securityType=2, password=3 }。"""
    validate_sta_ssid(ssid)
    validate_sta_password(security, password)
    return b"".join(
        (
            protobuf_string(1, ssid),
            protobuf_int(2, security),
            protobuf_string(3, password),
        )
    )


async def sta_connect(
    link: Np1Link, ssid: str, security: int, password: str, timeout: float
) -> bool:
    """0x0500/9 ApConnectRequest。SSID/鍵を本体へ渡して接続させる。"""
    payload = sta_connect_payload(ssid, security, password)
    # payload に PSK が平文で入るので hex をログに出さない
    request_id = await link.send(
        FUNC_WIFI_STA, OP_STA_CONNECT_REQUEST, payload, redact=True
    )
    response = await link.expect(
        FUNC_WIFI_STA, OP_STA_CONNECT_REQUEST | 0x8000, timeout, request_id
    )
    fields = parse_protobuf(response)
    log("[+] 0x0500/0x8009 ApConnectResponse")
    return log_result_error(fields)


async def sta_forget(
    link: Np1Link, ssid: str, security: int, timeout: float
) -> bool:
    """0x0500/7 RegisteredApDeleteRequest。登録済み AP を1件消す。"""
    validate_sta_ssid(ssid)
    fields = await sta_request(
        link,
        OP_STA_DELETE_REGISTERED_AP_REQUEST,
        protobuf_string(1, ssid) + protobuf_int(2, security),
        timeout,
    )
    log("[+] 0x0500/0x8007 RegisteredApDeleteResponse")
    return log_result_error(fields)


async def wifi_provision(
    link: Np1Link,
    ssid: str,
    security: int,
    password: str,
    timeout: float,
) -> bool:
    """STA を ON にしてから接続要求を出し、結果を読み直すところまで通す。

    STA が OFF のまま 0x0500/9 を送ると ERR_STA_SETTING で弾かれるので、
    順番は固定。
    """
    log("")
    log("[*] --- 外部 Wi-Fi (STA) 設定 ---")
    await sta_info(link, timeout)
    log("")
    log("[*] STA を ON にします")
    await sta_set_enabled(link, True, timeout)
    log("")
    log(f"[*] {ssid!r} へ接続要求 (security={enum_name(STA_SECURITIES, security)})")
    ok = await sta_connect(link, ssid, security, password, timeout)
    log("")
    log("[*] 接続状態を読み直します")
    await sta_info(link, timeout)
    await sta_connecting_ap(link, timeout)
    log("[*] --- ここまで ---")
    return ok


# --------------------------------------------------------------------------
# 取付設定 / 車内 AP / RTSP streaming (Function 0x0701)
# --------------------------------------------------------------------------


async def installation_bool_request(
    link: Np1Link,
    opcode: int,
    response_opcode: int,
    payload: bytes,
    timeout: float,
    *,
    request_id: int | None = None,
) -> bool:
    """DriveRec の InstallationSettingOperationSystem bool 応答を読む。"""
    request_id = await link.send(
        FUNC_INSTALLATION_SETTING, opcode, payload, request_id=request_id
    )
    response = await link.expect(
        FUNC_INSTALLATION_SETTING, response_opcode, timeout, request_id
    )
    return bool(int_or_zero(parse_protobuf(response), 1))


async def installation_local_ap(link: Np1Link, timeout: float) -> dict[str, Any]:
    """0x0701/12 LocalApSettingRequest。

    wire 形式は DriveRec の InstallationSettingOperationSystem.proto、APK の
    ma/d.java:560-570。password は受信 PDU のログにも出さない。
    """
    request_id = await link.send(
        FUNC_INSTALLATION_SETTING, OP_LOCAL_AP_SETTING_REQUEST, b""
    )
    response = await link.expect(
        FUNC_INSTALLATION_SETTING,
        OP_LOCAL_AP_SETTING_RESPONSE,
        timeout,
        request_id,
        redact=True,
    )
    fields = parse_protobuf(response)
    return {
        "ssid": protobuf_str_field(fields, 1, "ssid"),
        "password": protobuf_str_field(fields, 2, "password"),
        "security": int_or_zero(fields, 3),
        "band": int_or_zero(fields, 4),
    }


async def wait_installation_accepting(
    link: Np1Link, timeout: float
) -> dict[str, Any]:
    """ESS が DEVICE_INSTALLATION / ACCEPTING になるまでreadで確認する。

    APK ed/i.java:569-575 は、通常接続済みstate 16でこの2条件を検出した後に
    Opcode 2を非Secure ControlPointへ送る。
    """
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = await link.read_edge_state()
        if last["startup_mode"] != 0 and last["certification"] != 0:
            log("[+] ESS = DEVICE_INSTALLATION / ACCEPTING")
            return last
        await asyncio.sleep(0.25)
    raise Np1Error(
        "取付開始後もESSがDEVICE_INSTALLATION / ACCEPTINGになりません: "
        f"{last}"
    )


async def installation_reauthenticate(
    link: Np1Link, model: str, timeout: float
) -> None:
    """通常sessionから取付用一時sessionへ、APK state 16→14→15通りに移る。

    ed/i.java:569-575 は保存済みtokenで署名したOpcode 2を非Secure
    ControlPointへ書く。応答のaccess token/secretを一時fieldへ保持し、以後は
    frame mode 3相当として0x0700/0x0701を非Secure ControlPointへ書く
    (ed/i.java:398-433,701-719,722-785)。
    """
    if link.control_point == CONTROL_POINT:
        raise Np1Error("既に取付用一時sessionです")
    normal = (link.access_token, link.secret)
    request_id = await link.send(
        0,
        2,
        protobuf_string(1, model),
        request_id=1,
        characteristic=CONTROL_POINT,
    )
    payload = await link.expect(0, 0x8002, timeout, request_id, redact=True)
    fields = parse_protobuf(payload)
    temporary_access_token = protobuf_str_field(fields, 1, "accessToken")
    temporary_secret = protobuf_str_field(fields, 3, "secret")
    if not temporary_access_token or not temporary_secret:
        raise Np1Error("取付用一時認証情報に空文字列があります")
    link._normal_credentials = normal
    link.access_token = temporary_access_token
    link.secret = temporary_secret
    link.control_point = CONTROL_POINT
    log("[+] 取付用一時認証成功。以後は非Secure ControlPointを使用します")


async def installation_start(
    link: Np1Link, model: str, timeout: float
) -> bool:
    """取付開始後、Communicationの60秒窓内に一時認証を完了する。"""
    ok = await installation_bool_request(
        link,
        OP_INSTALLATION_START_REQUEST,
        OP_INSTALLATION_START_RESPONSE,
        b"",
        timeout,
    )
    if not ok:
        return False
    await wait_installation_accepting(link, timeout)
    await installation_reauthenticate(link, model, timeout)
    return True


# --------------------------------------------------------------------------
# 高レベルフロー
# --------------------------------------------------------------------------


async def do_pair(
    link: Np1Link,
    edge: dict[str, Any],
    model: str,
    user_key: str,
    response_timeout: float,
) -> dict[str, Any]:
    state = await link.read_edge_state()
    if state["startup_mode"] != 0 or state["certification"] == 0:
        raise Np1Error(
            "Opcode 2 送信接続で NORMAL / ACCEPTING ではありません: "
            f"StartupMode={state['startup_mode']} Certification={state['certification']}"
        )
    tokens = await issue_tokens(link, model, response_timeout)
    link.access_token = tokens["access_token"]
    link.secret = tokens["secret"]
    active_user_key = await activate_user_key(link, user_key, response_timeout)
    return {
        "device_name": None,
        "client_model": model,
        "version_firm": edge["version_firm"],
        "version_platform": edge["version_platform"],
        "version_boot": edge["version_boot"],
        "device_no": edge["device_no"],
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "secret": tokens["secret"],
        "user_key": active_user_key,
    }


async def do_reconnect_auth(
    link: Np1Link,
    ble: dict[str, Any],
    user_key: str | None,
    response_timeout: float,
    skip_user_key: bool,
    skip_persistence_wait: bool = False,
) -> dict[str, Any]:
    link.access_token = ble["access_token"]
    link.secret = ble["secret"]
    await link.read_edge_state()
    updated = await challenge(
        link, ble.get("client_model") or client_model(), ble["refresh_token"], response_timeout
    )
    credential_changed = updated is not None
    if updated:
        ble = {**ble, **updated}
    if skip_user_key:
        log("[*] --skip-user-key のため Opcode 8/10 を省略します")
    elif not user_key:
        log("[!] account userKey が無いため Opcode 8/10 を省略します")
    else:
        previous_user_key = ble.get("user_key")
        active_user_key = await activate_user_key(link, user_key, response_timeout)
        if active_user_key is not None:
            ble = {**ble, "user_key": active_user_key}
            credential_changed = credential_changed or (
                active_user_key != previous_user_key
            )

    silent = await enforce_silent_initial_setup(
        link, response_timeout, force_mute_request=False
    )
    ble = {
        **ble,
        "mute": silent["mute"],
        "master_volume": silent["volume"],
        "initial_setup_status": silent["initial_setup_status"],
    }
    setting_changed = (
        silent["mute_request_sent"]
        or silent["volume_request_sent"]
        or silent["initial_setup_notify_sent"]
    )
    if credential_changed:
        ble.pop("persistence_window_completed_at", None)
        if skip_persistence_wait:
            log("[*] --skip-persistence-wait のため credential 保存周期の待機を省略します")
            ble["persistence_window_skipped"] = True
        else:
            await wait_for_pair_persistence_window(link)
            ble.pop("persistence_window_skipped", None)
            ble["persistence_window_completed_at"] = dt.datetime.now(
                dt.timezone.utc
            ).isoformat()
    elif setting_changed:
        await wait_for_setting_persistence_window()
    return ble


def resolve_password(args: argparse.Namespace) -> str:
    if args.password is not None:
        return args.password
    key = args.mode_password
    if key not in MAINTENANCE_PASSWORDS:
        raise Np1Error(f"未知の --mode-password です: {key}")
    return MAINTENANCE_PASSWORDS[key]


def persist(path: Path, payload: dict[str, Any], ble: dict[str, Any], http: dict[str, Any] | None) -> None:
    payload = dict(payload)
    existing = payload.get("ble")
    payload["ble"] = {**existing, **ble} if isinstance(existing, dict) else dict(ble)
    if http is not None:
        payload["http"] = http
    save_session(path, payload)
    log(f"[+] session を保存しました: {path}")


# --------------------------------------------------------------------------
# コマンド
# --------------------------------------------------------------------------


# ed/i.java: `getBondState() == BOND_BONDED || versionFirm < 5.0001f`
# これを満たさないと、アプリは GATT を切って createBond() へ回る。
BOND_REQUIRED_FIRMWARE = 5.0001


def firmware_requires_bond(version_firm: str) -> bool:
    """このファームで、アプリが OS bond を必須にするか。"""
    try:
        return float(version_firm) >= BOND_REQUIRED_FIRMWARE
    except (TypeError, ValueError):
        # 読めないなら厳しい側に倒す
        return True


async def ensure_bond_like_app(transport, edge: dict[str, Any]) -> bool:
    """アプリの bond 要求を再現する。

    アプリは通常ペアリングで bond を張り、以後の再接続は
    `getBondState() == BOND_BONDED` の機器だけを対象にする
    (`ed/i.java` の scan mode 2)。本体側も SMP のペア情報を
    `/SETUP/BLERegData.dat` に持つ (`Communication` の `DeviceMgrTaurus`)。
    `/SETUP/FreeStyleLink/devices.dat` は別物で、Opcode 2 が発行する
    access/refresh token と secret の保存先である。
    """
    version = str(edge.get("version_firm", ""))
    if not firmware_requires_bond(version):
        log(f"[*] FW {version} は {BOND_REQUIRED_FIRMWARE} 未満。アプリも bond を求めません")
        return True
    log(
        f"[*] FW {version} は {BOND_REQUIRED_FIRMWARE} 以上。"
        "アプリはここで createBond() します (ed/i.java)"
    )
    return await transport.ensure_bond()


async def command_pair(transport, args: argparse.Namespace, run_maintenance: bool) -> int:
    session = load_session(args.session)
    http = session.get("http") if isinstance(session.get("http"), dict) else None

    user_key = args.user_key
    if user_key is None and http:
        user_key = http.get("user_key")
    if user_key is None:
        email = args.email or input("My NP1 メールアドレス: ").strip()
        password = args.account_password or getpass.getpass("My NP1 パスワード: ")
        http = http_login(email, password, args.user_agent)
        user_key = http["user_key"]
        log("[+] HTTP ログイン成功。userKey を取得")
    else:
        log("[*] 保存済み userKey を使用します")

    model = args.client_model or client_model()
    log(f"[*] client model (Build.MODEL 相当) = {model}")
    log("[*] NP1 側面の中央○ボタンを2秒長押しして通常ペアリング待受にしてください")

    edge, device = await wait_for_pairing_mode(
        transport, args.device_name, args.mode_timeout
    )
    log("[+] NORMAL / ACCEPTING を検出。GATT を切って3秒待ちます (ed/i.java 相当)")
    await asyncio.sleep(3.0)
    async with connect_with_retry(
        transport,
        device.name or args.device_name,
        device.address,
        args.scan_timeout,
        args.gatt_timeout,
        args.connect_timeout,
        pair=firmware_requires_bond(str(edge.get("version_firm", ""))),
    ) as (link, device):
        bond_ready = await ensure_bond_like_app(transport, edge)
        if firmware_requires_bond(str(edge.get("version_firm", ""))) and not bond_ready:
            raise Np1Error(
                "BlueZ Pair() が成功していないため、永続pairとして続行しません"
            )
        ble = await do_pair(link, edge, model, user_key, args.response_timeout)
        ble["device_name"] = device.name or args.device_name
        ble["ble_address"] = device.address
        # まずクライアント側の token を失わないよう保存する。続く mute/setup や
        # 60 秒待機が中断されても、同じ資格情報で再接続を試せる。
        persist(args.session, session, ble, http)
        silent = await enforce_silent_initial_setup(
            link, args.response_timeout, force_mute_request=True
        )
        ble.update(
            {
                "mute": silent["mute"],
                "master_volume": silent["volume"],
                "initial_setup_status": silent["initial_setup_status"],
            }
        )
        persist(args.session, session, ble, http)
        if args.skip_persistence_wait:
            log("[*] --skip-persistence-wait のため credential 保存周期の待機を省略します")
            ble["persistence_window_skipped"] = True
        else:
            await wait_for_pair_persistence_window(link)
            ble["persistence_window_completed_at"] = dt.datetime.now(
                dt.timezone.utc
            ).isoformat()
        persist(args.session, session, ble, http)
        if not run_maintenance:
            return 0
        return await _run_maintenance(link, args)


async def command_enter(transport, args: argparse.Namespace) -> int:
    if args.fresh:
        return await command_pair(transport, args, run_maintenance=True)

    session = load_session(args.session)
    ble = session.get("ble")
    if not isinstance(ble, dict) or not ble.get("access_token"):
        raise Np1Error(
            f"session に BLE 認証情報がありません: {args.session}\n"
            "先に `np1_maint.py pair` か `np1_maint.py enter --fresh` を実行してください"
        )
    http = session.get("http") if isinstance(session.get("http"), dict) else None
    user_key = args.user_key or (http.get("user_key") if http else None)

    address = ble.get("ble_address")
    async with connect_with_retry(
        transport,
        args.device_name or ble.get("device_name"),
        address,
        args.scan_timeout,
        args.gatt_timeout,
        args.connect_timeout,
        # アプリは bond 済みの機器にしか繋ぎに行かない (ed/i.java scan mode 2)
        pair=firmware_requires_bond(str(ble.get("version_firm", ""))),
    ) as (link, _device):
        ble = await do_reconnect_auth(
            link, ble, user_key, args.response_timeout, args.skip_user_key,
            skip_persistence_wait=args.skip_persistence_wait,
        )
        persist(args.session, session, ble, None)
        return await _run_maintenance(link, args)


async def edge_login_info(link: Np1Link, timeout: float) -> int:
    """0x0302/1 GET_LOGIN_INFO_REQUEST。本体のログイン状態を読む。"""
    request_id = await link.send(FUNC_EDGE_INFO, OP_GET_LOGIN_INFO_REQUEST, b"")
    response = await link.expect(
        FUNC_EDGE_INFO, OP_GET_LOGIN_INFO_RESPONSE, timeout, request_id
    )
    info = int_or_zero(parse_protobuf(response), 1)
    log(f"    loginInfo = {info} ({enum_name(LOGIN_INFO, info)})")
    return info


async def edge_login(
    link: Np1Link, refresh_token: str, user_key: str, timeout: float
) -> bool:
    """0x0302/2 LOGIN_REQUEST{ refresh_token=2, user_key=3 }。

    np1ctl.py command_setup と同じで、owner の member token から取った
    refreshToken / userKey を渡す。これに成功すると本体が
    AL_AccountService::GetOwnersToken() を作れるようになり、
    0x0900/1 CHECK_DATA が CHECK_FAILED を返さなくなる。
    """
    payload = protobuf_string(2, refresh_token) + protobuf_string(3, user_key)
    # refresh token が平文で入るので hex をログに出さない
    request_id = await link.send(
        FUNC_EDGE_INFO, OP_LOGIN_REQUEST, payload, redact=True
    )
    response = await link.expect(
        FUNC_EDGE_INFO, OP_LOGIN_RESPONSE, timeout, request_id
    )
    result = bool(int_or_zero(parse_protobuf(response), 1))
    log(f"[{'+' if result else '!'}] 0x0302/0x8002 LoginResponse result={result}")
    return result


async def do_edge_login(link: Np1Link, args: argparse.Namespace) -> bool:
    """session.json のアカウントで本体を My NP1 へログインさせる。

    1. 期限が近ければ account access token を refresh して保存し直す
       (refresh token はローテーションするので保存を落とすと次回詰む)
    2. owner の member token を取る
    3. その refreshToken / userKey を 0x0302/2 で本体へ渡す
    4. 0x0302/1 でログイン状態が LOGGED_IN になるまで確認する
    """
    session = load_session(args.session)
    http = session.get("http") if isinstance(session.get("http"), dict) else {}
    ble = session.get("ble") if isinstance(session.get("ble"), dict) else {}
    device_no = ble.get("device_no")
    if not device_no:
        raise Np1Error(f"session に device_no がありません: {args.session}")

    access_token = http.get("access_token")
    if not access_token or http_token_expired(http):
        refresh_token = http.get("refresh_token")
        if not refresh_token:
            raise Np1Error(
                "account access token が無効で refresh token もありません。"
                "np1_ota.py --send などでログインし直してください"
            )
        log("[*] account access token を refresh します")
        http = await asyncio.to_thread(http_refresh, refresh_token, args.user_agent)
        persist(args.session, session, {}, http)
        access_token = http["access_token"]
        log("[+] refresh 成功 (session.json を更新しました)")

    log("[*] owner の member token を取得します")
    member = await asyncio.to_thread(
        get_member_token, access_token, device_no, "owner", args.user_agent
    )
    log("[+] member token 取得 (target=owner)")

    if not await edge_login(
        link, member["refresh_token"], member["user_key"], args.response_timeout
    ):
        return False

    for attempt in range(10):
        await asyncio.sleep(1.0)
        info = await edge_login_info(link, args.response_timeout)
        if info == 1:
            log("[+] 本体が LOGGED_IN になりました")
            return True
        log(f"[*] まだ LOGGED_IN ではありません ({attempt + 1}/10)")
    return False


async def update_check(link: Np1Link, timeout: float) -> dict[str, Any]:
    """0x0900/1 CHECK_DATA_REQUEST。

    本体が OTA サーバーへ問い合わせて結果を返す。こちら側にクラウドの
    認証情報は要らない。

    **読み取りだけでは済まない。** 2026-09-20 の実測では、更新が見つかると
    本体がそのままダウンロードから適用まで自分で進めた。

        result=2 NEW_DATA_FOUND
          -> 3 NEW_DATA_DOWNLOADING (progress 1 -> 10 -> 15 ...)
          -> 5 NEW_DATA_UPDATE_FINISHED

    `Update` に `CUPD_SRV_PRG_SIGNAL_START_DOWNLOAD_AUTO` があり、
    自動ダウンロードの経路が最初から用意されている。適用が終わっても
    EdgeSystemState の version_firm は変わらない (A/B の非稼働側へ書く)。**現在のファームを残したいなら、この
    コマンドを叩く前に 0x0900/3 FIRMWARE_DOWNLOAD_CANCEL_REQUEST を
    使える状態にしておくこと。**
    """
    request_id = await link.send(
        FUNC_PROGRAM_UPDATE, OP_CHECK_DATA_REQUEST, b""
    )
    payload = await link.expect(
        FUNC_PROGRAM_UPDATE, OP_CHECK_DATA_RESPONSE, timeout, request_id
    )
    fields = parse_protobuf(payload)
    result = fields.get(1, 0)
    return {
        "result": result if isinstance(result, int) else 0,
        "software_version": protobuf_str_field_or_default(fields, 2),
        "update_data_size": protobuf_str_field_or_default(fields, 3),
        "estimated_update_time": protobuf_str_field_or_default(fields, 4),
        "progress": protobuf_str_field_or_default(fields, 5),
    }


def protobuf_str_field_or_default(fields: dict[int, Any], number: int) -> str:
    value = fields.get(number)
    if not isinstance(value, bytes):
        return ""
    return value.decode("utf-8", "replace")


async def _report_serial_status(link: Np1Link, args: argparse.Namespace) -> dict[str, bool]:
    status = await serial_get_status(link, args.response_timeout)
    log(
        "[+] DebugSerialPortIO: "
        f"result={status['result']} "
        f"outputStatus(ログ出力)={status['output_status']} "
        f"inputStatus(コンソール入力)={status['input_status']}"
    )
    return status


SHELL_HELP = """使えるコマンド:
  status              EdgeSystemState を読む
  mode                現在の MaintenanceMode を照会 (0xE000/5)
  enter [pw-key]      Maintenance Mode へ移行 (既定 poseidon-on)
  exit                移行フローを打ち切る (0xE000/3)
  serial-status       シリアル設定を読む (0xF00D/1)
  serial-console on|off   コンソール入力を切り替え (0xF00D/3)
  serial-log on|off       デバッグログ出力を切り替え (0xF00D/2)
  volume              音量・mute・補正を読む (0x0400/1)
  mute                mute ON を送信し、読み返しで確認 (0x0400/3 → 1)
  setup-status        初期設定完了状態を読む (0x0200/1)
  silent-setup        mute ON → 初期設定完了を再確認する
  update-check        OTA 更新確認 (0x0900/1)
  wifi / wifi-status  外部Wi-Fi(STA)の状態を読む (0x0500/1)
  wifi on|off         STA を切り替える (0x0500/2)
  wifi-scan [page]    本体が見ている周辺APを列挙 (0x0500/5、1ページ5件)
  wifi-saved [page]   本体に登録済みのAPを列挙 (0x0500/4)
  wifi-current        いま接続しているAP (0x0500/6)
  wifi-connect <ssid> [open|wpa1-wpa2|wpa2-wpa3]
                      外部Wi-Fiへ接続 (0x0500/2 → 9)。既定は wpa1-wpa2。
                      鍵は非表示プロンプト（NP1_WIFI_PASSWORD があればそれを使う）
  wifi-forget <ssid> [security]   登録済みAPを1件削除 (0x0500/7)
  install-status      取付設定状態を照会 (0x0701/1)
  install-ap          車内AP設定を取得し session に保存 (0x0701/12、鍵は非表示)
  install-start       取付設定と映像配信を開始 (0x0701/2)
  install-live        取付モード生存確認を1回送信 (0x0701/6)
  install-switch front|in  配信カメラを切り替え (0x0701/11)
  install-cancel      取付設定を中止 (0x0701/3)
  raw <func> <op> [hex]   任意の Function を直接叩く (func/op は 16 進)
  help                この一覧
  quit                接続を閉じて終了
"""


def _page_arg(rest: list[str]) -> int:
    """ページ番号は 1 始まり。未指定は 1。"""
    if not rest:
        return 1
    page = int(rest[0])
    if page < 1:
        raise Np1Error("page は 1 以上です")
    return page


# serve 経由のとき、call が送ってきた鍵をここへ置く。
_REQUEST_PASSWORD: str | None = None


async def _ask_wifi_password() -> str:
    """鍵は端末にもチャットにも出さない。

    優先順位は call が送ってきた鍵 > NP1_WIFI_PASSWORD > 非表示プロンプト。
    常駐 (serve) は stdin を持たないので、socket 越しに受け取る経路が要る。
    """
    if _REQUEST_PASSWORD:
        log("[*] call から渡された鍵を使います")
        return _REQUEST_PASSWORD
    from_env = os.environ.get("NP1_WIFI_PASSWORD")
    if from_env:
        log("[*] NP1_WIFI_PASSWORD を使います")
        return from_env
    return await asyncio.to_thread(getpass.getpass, "外部Wi-Fi password: ")


async def _shell(
    link: Np1Link,
    args: argparse.Namespace,
    read_line: Callable[[], Awaitable[str]] | None = None,
    banner: bool = True,
) -> int:
    """GATT 接続を保持したまま、複数のコマンドを続けて実行する。

    本体は一度切断すると再接続を受け付けないことが多いので、
    1 本の接続でやりたいことを全部やり切るためのループ。

    ``read_line`` を渡すと入力元を差し替えられる。``serve`` は
    これで UNIX socket から来た行を流し込み、同じ分岐をそのまま使う。
    """
    if banner:
        log("")
        log("=" * 60)
        log("[+] 接続を保持しています。切断せずに続けて操作できます。")
        log(SHELL_HELP)
    entered_mode: int | None = None

    while True:
        try:
            if read_line is None:
                line = (await asyncio.to_thread(input, "np1> ")).strip()
            else:
                line = (await read_line()).strip()
        except (EOFError, KeyboardInterrupt):
            log("")
            break
        if not line:
            continue
        try:
            # SSID に空白が入ることがあるので "..." を解釈する
            parts = shlex.split(line)
        except ValueError as error:
            log(f"[!] 引用符が閉じていません: {error}")
            continue
        if not parts:
            continue
        cmd, rest = parts[0].lower(), parts[1:]
        try:
            if cmd in ("quit", "exit-shell", "q"):
                break
            if cmd == "help":
                log(SHELL_HELP)
            elif cmd == "status":
                state = await link.read_edge_state()
                for key, value in state.items():
                    log(f"    {key} = {value}")
            elif cmd == "mode":
                mode = await maintenance_query_mode(link, args.response_timeout)
                log(f"[+] MaintenanceMode = {describe_mode(mode)}")
            elif cmd == "enter":
                key = rest[0] if rest else "poseidon-on"
                if key not in MAINTENANCE_PASSWORDS:
                    log(f"[!] 未知のパスワード名: {key} "
                        f"({', '.join(sorted(MAINTENANCE_PASSWORDS))})")
                    continue
                entered_mode = await maintenance_enter(
                    link,
                    MAINTENANCE_PASSWORDS[key],
                    args.key_timeout,
                    args.response_timeout,
                )
                log(f"[+] mode = {describe_mode(entered_mode)}")
                if entered_mode not in (0, 1):
                    await verify_maintenance(link, entered_mode, args)
            elif cmd == "exit":
                await maintenance_exit(link)
            elif cmd == "serial-status":
                await _report_serial_status(link, args)
            elif cmd in ("serial-console", "serial-log"):
                if not rest or rest[0] not in ("on", "off"):
                    log("[!] on か off を指定してください")
                    continue
                on = rest[0] == "on"
                opcode, response = (
                    (OP_SERIAL_CONSOLE_INPUT_SWITCH_REQUEST,
                     OP_SERIAL_CONSOLE_INPUT_SWITCH_RESPONSE)
                    if cmd == "serial-console"
                    else (OP_SERIAL_LOG_OUTPUT_SWITCH_REQUEST,
                          OP_SERIAL_LOG_OUTPUT_SWITCH_RESPONSE)
                )
                ok = await serial_switch(link, opcode, response, on, args.response_timeout)
                log(f"[{'+' if ok else '!'}] result={ok}")
                await _report_serial_status(link, args)
            elif cmd == "volume":
                await volume_setting_status(link, args.response_timeout)
            elif cmd == "mute":
                await set_mute(link, True, args.response_timeout)
                await wait_for_setting_persistence_window()
            elif cmd == "setup-status":
                await initial_setup_status(link, args.response_timeout)
            elif cmd == "silent-setup":
                silent = await enforce_silent_initial_setup(
                    link,
                    args.response_timeout,
                    force_mute_request=True,
                )
                if (
                    silent["mute_request_sent"]
                    or silent["volume_request_sent"]
                    or silent["initial_setup_notify_sent"]
                ):
                    await wait_for_setting_persistence_window()
            elif cmd == "update-check":
                info = await update_check(link, args.response_timeout)
                log(f"    result              = {info['result']} "
                    f"({CHECK_DATA_RESULTS.get(info['result'], 'UNRECOGNIZED')})")
                log(f"    softwareVersion     = {info['software_version']!r}")
                log(f"    updateDataSize      = {info['update_data_size']!r}")
                log(f"    estimatedUpdateTime = {info['estimated_update_time']!r}")
                log(f"    progress            = {info['progress']!r}")
            elif cmd in ("wifi", "wifi-status"):
                if rest and rest[0] in ("on", "off"):
                    await sta_set_enabled(link, rest[0] == "on", args.response_timeout)
                    await sta_info(link, args.response_timeout)
                elif rest:
                    log("[!] wifi [on|off]")
                else:
                    await sta_info(link, args.response_timeout)
            elif cmd == "wifi-scan":
                await sta_nearby(link, _page_arg(rest), args.response_timeout)
            elif cmd == "wifi-saved":
                await sta_registered(link, _page_arg(rest), args.response_timeout)
            elif cmd == "wifi-current":
                await sta_connecting_ap(link, args.response_timeout)
            elif cmd == "wifi-connect":
                if not rest:
                    log('[!] wifi-connect <ssid> [open|wpa1-wpa2|wpa2-wpa3]')
                    continue
                security = security_type(rest[1] if len(rest) > 1 else "wpa1-wpa2")
                password = "" if security == 1 else await _ask_wifi_password()
                ok = await wifi_provision(
                    link, rest[0], security, password, args.response_timeout
                )
                log(f"[{'+' if ok else '!'}] 接続要求の結果: {'SUCCESS' if ok else 'ERROR'}")
            elif cmd == "wifi-forget":
                if not rest:
                    log("[!] wifi-forget <ssid> [security]")
                    continue
                security = security_type(rest[1] if len(rest) > 1 else "wpa1-wpa2")
                await sta_forget(link, rest[0], security, args.response_timeout)
            elif cmd == "install-status":
                ok = await installation_bool_request(
                    link,
                    OP_INSTALLATION_STATUS_REQUEST,
                    OP_INSTALLATION_STATUS_RESPONSE,
                    b"",
                    args.response_timeout,
                )
                log(f"[+] InstallationStatus result={ok}")
            elif cmd == "install-ap":
                info = await installation_local_ap(link, args.response_timeout)
                session = load_session(args.session)
                session["local_ap"] = info
                save_session(args.session, session)
                log("[+] LocalApSettingResponse")
                log(f"    ssid     = {info['ssid']!r}")
                log(f"    password = <{len(info['password'])} chars 非表示>")
                log(
                    "    security = "
                    f"{info['security']} ({STA_SECURITIES.get(info['security'], 'UNRECOGNIZED')})"
                )
                log(
                    f"    band     = {info['band']} "
                    f"({INSTALLATION_BANDS.get(info['band'], 'UNRECOGNIZED')})"
                )
                log(f"[+] session に保存しました: {args.session}")
            elif cmd == "install-start":
                session = load_session(args.session)
                ble = session.get("ble")
                saved_model = (
                    ble.get("client_model") if isinstance(ble, dict) else None
                )
                model = args.client_model or saved_model or client_model()
                ok = await installation_start(link, model, args.response_timeout)
                log(f"[+] InstallationSettingStart result={ok}")
            elif cmd == "install-live":
                ok = await installation_bool_request(
                    link,
                    OP_LIVING_CONFIRMATION_REQUEST,
                    OP_LIVING_CONFIRMATION_RESPONSE,
                    b"",
                    args.response_timeout,
                    request_id=1,
                )
                log(f"[+] LivingConfirmation result={ok}")
            elif cmd == "install-switch":
                if not rest or rest[0] not in INSTALLATION_CAMERAS:
                    log("[!] install-switch front|in")
                    continue
                ok = await installation_bool_request(
                    link,
                    OP_SWITCH_VIDEO_STREAMING_REQUEST,
                    OP_SWITCH_VIDEO_STREAMING_RESPONSE,
                    protobuf_int(1, INSTALLATION_CAMERAS[rest[0]]),
                    args.response_timeout,
                )
                log(f"[+] SwitchVideoStreaming camera={rest[0]} result={ok}")
            elif cmd == "install-cancel":
                await link.send(
                    FUNC_INSTALLATION_SETTING,
                    OP_INSTALLATION_CANCEL_NOTIFY,
                    b"",
                    expect_response=False,
                )
                log("[+] InstallationCancelNotify を送信しました")
            elif cmd == "raw":
                if len(rest) < 2:
                    log("[!] raw <func> <op> [hex]")
                    continue
                # 貼り付けが連結して "6update-check" のような値が届くことが
                # あるので、16 進として妥当かを先に見る。
                try:
                    function_id = int(rest[0], 16)
                    opcode = int(rest[1], 16)
                    payload = bytes.fromhex(rest[2]) if len(rest) > 2 else b""
                except ValueError as error:
                    log(f"[!] raw の引数が 16 進として読めません: {error}")
                    log(f"[!] 受け取った引数: {rest}")
                    continue
                request_id = await link.send(function_id, opcode, payload)
                # 同じ functionId の応答が来るまで読み飛ばす。
                # 直前のコマンドの応答がキューに残っていることがある。
                deadline = time.monotonic() + args.response_timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        log("[!] 対象 functionId の応答が来ませんでした")
                        break
                    _s, got_f, got_op, got_r, got_payload = await link.next_pdu(
                        remaining
                    )
                    if got_f != function_id:
                        log(f"[*] 古い応答を読み飛ばし (function=0x{got_f:04x} "
                            f"opcode=0x{got_op:04x})")
                        continue
                    log(f"[+] function=0x{got_f:04x} opcode=0x{got_op:04x} "
                        f"payload={got_payload.hex() or '(empty)'} "
                        f"(reqId={got_r}, 送信時 {request_id})")
                    break
            else:
                log(f"[!] 未知のコマンド: {cmd}")
        except Np1Error as error:
            log(f"[!] {error}")
        except GATT_ERRORS as error:
            log(f"[!] BLE エラー: {type(error).__name__}: {error}")
            log("[!] 接続が切れた可能性があります。quit して張り直してください")
        except Exception as error:  # noqa: BLE001
            # 本体は切断後の再接続を受け付けないことが多い。入力ミス程度で
            # プロセスが死ぬと、張り直しのきかない接続を失う。
            # ここで握りつぶさず内容を出したうえで、ループだけは続ける。
            log(f"[!] コマンド {cmd!r} の処理で例外: "
                f"{type(error).__name__}: {error}")
            log("[!] 接続は維持しています。入力を直してもう一度どうぞ")
    log("[*] 接続を閉じます")
    return 0


async def _keepalive(
    link: Np1Link,
    busy: Callable[[], bool],
    interval: float,
    heartbeat_interval: float = 10.0,
) -> None:
    """アプリと同じ取付モード heartbeat を送り、GATT も維持する。

    APK ed/i.java:426-433 は Function 0x0701 / Opcode 6 を、初回10秒・
    以後10秒周期で送る。DriveRec 0xfb280 / 0xfb328 は受信のたびに
    30,000 ms の InstSurvivalTimer を停止・再始動する。

    これは Communication 0x1dc5e8 の 60,000 ms PairingModeTimer とは別物。
    同timerは取付開始時に始まり、ペアリング完了前に満了すると0x1de084から
    RequestCDVRCancelInstallationMode()を発行する。Opcode 6では停止しない。
    コマンド処理中または socket request 待ち行列がある間は送らない。
    """
    edge_elapsed = 0.0
    while True:
        await asyncio.sleep(heartbeat_interval)
        if busy():
            continue
        try:
            ok = await installation_bool_request(
                link,
                OP_LIVING_CONFIRMATION_REQUEST,
                OP_LIVING_CONFIRMATION_RESPONSE,
                b"",
                20.0,
                # APK ed/h.java:20-24 はこの timer PDU の flag/requestId を
                # 毎回 1 に固定する。
                request_id=1,
            )
            debug(f"[*] keepalive: LivingConfirmation result={ok}")
            edge_elapsed += heartbeat_interval
            if edge_elapsed >= interval:
                await link.read_edge_state()
                edge_elapsed = 0.0
                debug("[*] keepalive: EdgeSystemState を読みました")
        except Exception as error:  # noqa: BLE001
            log(f"[!] keepalive 失敗: {type(error).__name__}: {error}")
            return


async def _serve(link: Np1Link, args: argparse.Namespace) -> int:
    """GATT 接続を保持したまま常駐し、UNIX socket からコマンドを受ける。

    接続を保持して、何度でもコマンドを流せるようにする。
    対話シェルと同じ分岐を使う。
    """
    path: Path = args.socket
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()

    requests: asyncio.Queue = asyncio.Queue()
    pending: list[tuple[asyncio.Future, list[str]]] = []

    def finish_previous() -> None:
        global _LOG_SINK, _REQUEST_PASSWORD
        while pending:
            future, sink = pending.pop()
            if not future.done():
                future.set_result(sink)
        _LOG_SINK = None
        _REQUEST_PASSWORD = None  # 鍵は 1 リクエスト限り

    async def read_line() -> str:
        global _LOG_SINK, _REQUEST_PASSWORD
        finish_previous()
        line, password, future = await requests.get()
        sink: list[str] = []
        pending.append((future, sink))
        _LOG_SINK = sink
        _REQUEST_PASSWORD = password
        return line

    async def handle(reader, writer) -> None:
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except ValueError as error:
                    answer = {"ok": False, "error": f"JSON として読めません: {error}"}
                else:
                    future = asyncio.get_running_loop().create_future()
                    secret = payload.get("password")
                    await requests.put(
                        (
                            str(payload.get("line", "")),
                            str(secret) if secret else None,
                            future,
                        )
                    )
                    answer = {"ok": True, "lines": await future}
                writer.write(
                    (json.dumps(answer, ensure_ascii=False) + "\n").encode("utf-8")
                )
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            return
        finally:
            with suppress(Exception):
                writer.close()

    server = await asyncio.start_unix_server(handle, path=str(path))
    path.chmod(0o600)
    log("")
    log("=" * 60)
    log(f"[+] 接続を保持したまま {path} で待ち受けます")
    log("[*] 別のターミナルから叩いてください:")
    log("[*]   .venv/bin/python np1_maint.py call status")
    log("[*]   .venv/bin/python np1_maint.py call wifi")
    log("[*]   .venv/bin/python np1_maint.py call wifi-scan")
    log("[*] Ctrl-C で終了します")
    log("")

    watcher = asyncio.create_task(
        _keepalive(
            link,
            lambda: bool(pending) or not requests.empty(),
            args.keepalive,
            getattr(args, "heartbeat_interval", 10.0),
        )
    )
    try:
        return await _shell(link, args, read_line=read_line, banner=False)
    finally:
        finish_previous()
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher
        server.close()
        with suppress(Exception):
            await server.wait_closed()
        with suppress(FileNotFoundError):
            path.unlink()


def _password_for(words: list[str]) -> str | None:
    """wifi-connect なら鍵を手元で用意する。socket 越しに 1 回だけ渡す。

    常駐側 (serve) は stdin を持たないので、プロンプトはこちらで出す。
    """
    if not words or words[0].lower() != "wifi-connect":
        return None
    security = words[2] if len(words) > 2 else "wpa1-wpa2"
    if security == "open":
        return None
    return os.environ.get("NP1_WIFI_PASSWORD") or getpass.getpass(
        "外部Wi-Fi password: "
    )


async def _call(args: argparse.Namespace) -> int:
    """常駐している serve へコマンドを 1 行投げて、結果を表示する。"""
    line = " ".join(args.words)
    password = _password_for(args.words)
    try:
        reader, writer = await asyncio.open_unix_connection(str(args.socket))
    except (FileNotFoundError, ConnectionRefusedError):
        log(f"[!] {args.socket} に繋がりません")
        log("[!] 先に `np1_maint.py serve --fresh` を起動してください")
        return 1
    try:
        request: dict[str, Any] = {"line": line}
        if password:
            request["password"] = password
        writer.write((json.dumps(request) + "\n").encode("utf-8"))
        await writer.drain()
        raw = await reader.readline()
    finally:
        with suppress(Exception):
            writer.close()
    if not raw:
        log("[!] serve から応答がありません（切断された可能性があります）")
        return 1
    answer = json.loads(raw.decode("utf-8"))
    if not answer.get("ok"):
        log(f"[!] {answer.get('error')}")
        return 1
    for entry in answer.get("lines", []):
        print(entry, flush=True)
    return 0


async def _list_all_pages(
    link: Np1Link, fetch, page: int | None, timeout: float
) -> int:
    """--page 指定があればその1ページ、なければ allNum を満たすまで辿る。"""
    if page is not None:
        await fetch(link, page, timeout)
        return 0
    current = 1
    collected = 0
    while True:
        fields = await fetch(link, current, timeout)
        collected += len(repeated(fields, 5))
        total = int_or_zero(fields, 4)
        if collected >= total or not repeated(fields, 5) or current >= 20:
            return 0
        current += 1


async def _run_wifi(link: Np1Link, args: argparse.Namespace) -> int:
    timeout = args.response_timeout
    if args.command == "wifi-status":
        await sta_info(link, timeout)
        await sta_connecting_ap(link, timeout)
        return 0
    if args.command == "wifi-scan":
        return await _list_all_pages(link, sta_nearby, args.page, timeout)
    if args.command == "wifi-saved":
        return await _list_all_pages(link, sta_registered, args.page, timeout)
    if args.command in ("wifi-on", "wifi-off"):
        ok = await sta_set_enabled(link, args.command == "wifi-on", timeout)
        await sta_info(link, timeout)
        return 0 if ok else 1
    if args.command == "wifi-forget":
        ok = await sta_forget(link, args.ssid, security_type(args.security), timeout)
        return 0 if ok else 1
    if args.command == "wifi-connect":
        security = security_type(args.security)
        if security == 1:
            password = ""
        elif args.password is not None:
            password = args.password
        else:
            password = await _ask_wifi_password()
        ok = await wifi_provision(link, args.ssid, security, password, timeout)
        log("")
        log(f"[{'+' if ok else '!'}] 接続要求の結果: {'SUCCESS' if ok else 'ERROR'}")
        return 0 if ok else 1
    raise Np1Error(f"未対応のコマンドです: {args.command}")


async def _run_maintenance(link: Np1Link, args: argparse.Namespace) -> int:
    if args.command == "reconnect":
        log("[+] 再接続と再認証に成功しました")
        state = await link.read_edge_state()
        for key, value in state.items():
            log(f"    {key} = {value}")
        return 0
    if args.command == "shell":
        return await _shell(link, args)
    if args.command == "serve":
        return await _serve(link, args)
    if args.command == "mode":
        mode = await maintenance_query_mode(link, args.response_timeout)
        log(f"[+] 現在の MaintenanceMode = {describe_mode(mode)}")
        return 0
    if args.command == "exit":
        await maintenance_exit(link)
        return 0

    if args.command == "update-check":
        info = await update_check(link, args.response_timeout)
        log("")
        log("[+] 0x0900/1 CHECK_DATA_RESPONSE")
        log(f"    result              = {info['result']} "
            f"({CHECK_DATA_RESULTS.get(info['result'], 'UNRECOGNIZED')})")
        log(f"    softwareVersion     = {info['software_version']!r}")
        log(f"    updateDataSize      = {info['update_data_size']!r}")
        log(f"    estimatedUpdateTime = {info['estimated_update_time']!r}")
        log(f"    progress            = {info['progress']!r}")
        return 0

    if args.command.startswith("wifi-"):
        return await _run_wifi(link, args)

    if args.command.startswith("serial-"):
        if args.enter:
            mode = await _enter_and_report(link, args)
            if mode in (0, 1):
                return 1
        if args.command == "serial-status":
            await _report_serial_status(link, args)
            return 0
        status = args.status == "on"
        if args.command == "serial-console":
            log(f"[*] シリアルコンソール入力を {args.status.upper()} にします")
            ok = await serial_switch(
                link,
                OP_SERIAL_CONSOLE_INPUT_SWITCH_REQUEST,
                OP_SERIAL_CONSOLE_INPUT_SWITCH_RESPONSE,
                status,
                args.response_timeout,
            )
        else:
            log(f"[*] デバッグシリアルログ出力を {args.status.upper()} にします")
            ok = await serial_switch(
                link,
                OP_SERIAL_LOG_OUTPUT_SWITCH_REQUEST,
                OP_SERIAL_LOG_OUTPUT_SWITCH_RESPONSE,
                status,
                args.response_timeout,
            )
        log(f"[{'+' if ok else '!'}] result={ok}")
        await _report_serial_status(link, args)
        return 0 if ok else 1

    mode = await _enter_and_report(link, args)
    if mode in (0, 1):
        return 1
    if not args.keep_open:
        return 0
    log("[*] --keep-open 指定のため接続を維持します。Ctrl-C で終了します")
    while True:
        with suppress(Np1Error):
            await link.next_pdu(3600.0)


async def verify_maintenance(
    link: Np1Link, expected: int, args: argparse.Namespace
) -> bool:
    """本当に Maintenance Mode に入れているかを実地で確かめる。

    PasswordVerificationResponse はパスワード判定の結果を返すだけなので、
    別コマンドで本体の状態を読み直して裏を取る。

      1. 0xE000/5 MaintenanceModeRequest で現在モードを照会する
      2. Maintenance Mode 専用の 0xF00D を実際に叩いてみる
         (入れていなければ FUNCTION_UNAVAILABLE 等で弾かれるはず)
    """
    ok = True
    log("")
    log("[*] --- Maintenance Mode の確認 ---")

    try:
        reported = await maintenance_query_mode(link, args.response_timeout)
        log(f"[*] 確認1: 0xE000/5 の返答 mode = {describe_mode(reported)}")
        if reported != expected:
            log(
                f"[!] 確認1: PasswordVerificationResponse ({describe_mode(expected)}) "
                f"と一致しません"
            )
            ok = False
        elif reported in (0, 1):
            log("[!] 確認1: OFF/DEFAULT のままです")
            ok = False
        else:
            log("[+] 確認1: 一致")
    except Np1Error as error:
        log(f"[!] 確認1: モード照会に失敗: {error}")
        ok = False

    try:
        status = await serial_get_status(link, args.response_timeout)
        log(
            "[+] 確認2: 0xF00D/1 が通りました "
            f"(result={status['result']} "
            f"outputStatus={status['output_status']} "
            f"inputStatus={status['input_status']})"
        )
        log("[+] 確認2: Maintenance 専用 Function が受理されています")
    except Np1Error as error:
        log(f"[!] 確認2: 0xF00D/1 が通りませんでした: {error}")
        log("[!] 確認2: Maintenance Mode が有効になっていない可能性があります")
        ok = False

    log("[*] --- 確認ここまで ---")
    return ok


async def _enter_and_report(link: Np1Link, args: argparse.Namespace) -> int:
    password = resolve_password(args)
    log(f"[*] 使用するパスワード: {password!r}")
    mode = await maintenance_enter(
        link,
        password,
        args.key_timeout,
        args.response_timeout,
        skip_start=args.skip_start,
    )
    log("")
    log(f"[+] PASSWORD_VERIFICATION_RESPONSE mode = {describe_mode(mode)}")
    if mode in (0, 1):
        log(
            "[!] OFF/DEFAULT が返りました。パスワード不一致か、state が 2 に"
            "なっていない可能性があります"
        )
        return mode
    log("[+] パスワード認証は通りました")

    if args.no_verify:
        log("[*] --no-verify 指定のため確認を省略します")
        return mode
    if await verify_maintenance(link, mode, args):
        log("")
        log(f"[+] Maintenance Mode ({MAINTENANCE_MODES.get(mode)}) で動作中と確認しました")
    else:
        log("")
        log("[!] Maintenance Mode に入れている確証が得られませんでした")
        return 1 if mode not in (0, 1) else mode
    return mode


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "NP1 のペアリングから Maintenance Mode 入場 "
            "(Function 0xE000 / Opcode 4) までを実行する"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "例:\n"
            "  np1_maint.py enter --fresh          # ペアリングから通しで実行\n"
            "  np1_maint.py enter                  # 保存済みsessionで再接続して入場\n"
            "  np1_maint.py enter --mode-password service-on\n"
            "  np1_maint.py mode                   # 現在のMaintenanceModeを照会\n"
            "  np1_maint.py serial-status          # 0xF00D/1 で現在設定を読む\n"
            "  np1_maint.py serial-console on --enter  # 移行してコンソール入力ON\n"
        ),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="詳細ログを出す")
    parser.add_argument(
        "--session", type=Path, default=DEFAULT_SESSION_PATH, help="session.json のパス"
    )
    parser.add_argument("--device-name", help="BLE local name (例 NP1-0974)")
    parser.add_argument("--client-model", help="Build.MODEL 相当。既定は Pi の platform.machine()")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--user-key", help="account userKey を直接指定する")
    parser.add_argument(
        "--email",
        default=os.environ.get("NP1_EMAIL"),
        help="My NP1 メールアドレス (未指定なら NP1_EMAIL)",
    )
    parser.add_argument(
        "--account-password",
        default=os.environ.get("NP1_PASSWORD"),
        help="My NP1 パスワード (未指定なら NP1_PASSWORD または非表示プロンプト)",
    )
    parser.add_argument("--scan-timeout", type=float, default=25.0)
    parser.add_argument(
        "--gatt-timeout", type=float, default=30.0, help="GATT 接続1回あたりのtimeout秒"
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=180.0,
        help="スキャン+GATT接続の再試行を打ち切る秒数。0 で無制限",
    )
    parser.add_argument(
        "--mode-timeout",
        type=float,
        default=0.0,
        help="ペアリング待受の検出待ち秒数。0 で無制限",
    )
    parser.add_argument("--response-timeout", type=float, default=20.0)
    parser.add_argument(
        "--key-timeout",
        type=float,
        default=FIRMWARE_KEY_TIMEOUT_SECONDS + 10.0,
        help="キー列一致通知 (0x8002) の待ち秒数",
    )
    parser.add_argument(
        "--skip-user-key",
        action="store_true",
        help="再接続時に Opcode 8/10 を省略する",
    )
    parser.add_argument(
        "--skip-persistence-wait",
        action="store_true",
        help="新規pair・資格情報更新後の65秒待機を省略する",
    )

    # Maintenance Mode への移行オプション。enter と serial-* で共通。
    entry_options = argparse.ArgumentParser(add_help=False)
    entry_options.add_argument(
        "--mode-password",
        default="poseidon-on",
        choices=sorted(MAINTENANCE_PASSWORDS),
        help="復号済みパスワードの選択 (既定: poseidon-on)",
    )
    entry_options.add_argument("--password", help="パスワード文字列を直接指定する")
    entry_options.add_argument(
        "--skip-start",
        action="store_true",
        help="0xE000/1 を送らず 0x8002 待ちから始める",
    )
    entry_options.add_argument(
        "--no-verify",
        action="store_true",
        help="移行後の確認 (0xE000/5 と 0xF00D/1) を省略する",
    )

    # 本体は一度切断すると再接続を受け付けない（このセッションでは再接続が
    # 一度も成功していない）。確実に繋ぐには新規ペアリングからやり直す。
    fresh_option = argparse.ArgumentParser(add_help=False)
    fresh_option.add_argument(
        "--fresh",
        action="store_true",
        help="先に新規ペアリングを行い、同じ接続のまま実行する"
        "（本体は切断後の再接続を受け付けないことが多い）",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("pair", help="ペアリングのみ実行して session を保存する")

    enter = subparsers.add_parser(
        "enter",
        parents=[entry_options, fresh_option],
        help="Maintenance Mode へ移行する (0xE000/1 → 0x8002 → 0xE000/4)",
    )
    enter.add_argument(
        "--keep-open",
        action="store_true",
        help="移行後も接続を維持して受信PDUを表示し続ける",
    )

    subparsers.add_parser(
        "update-check",
        parents=[fresh_option],
        help="本体に OTA の更新確認をさせる (0x0900/1)。Maintenance Mode 不要。"
        "更新があると本体がそのままダウンロードして適用する",
    )
    subparsers.add_parser(
        "shell",
        parents=[fresh_option],
        help="GATT 接続を保持したまま対話的に操作する"
        "（切断後は再接続できないことが多いので、これで一気にやる）",
    )
    serve = subparsers.add_parser(
        "serve",
        parents=[fresh_option],
        help="GATT 接続を保持したまま常駐し、UNIX socket でコマンドを受ける"
        "（切断すると繋ぎ直せないので、繋ぎっぱなしにするための常駐モード）",
    )
    serve.add_argument("--socket", type=Path, default=DEFAULT_SOCKET_PATH)
    serve.add_argument(
        "--keepalive",
        type=float,
        default=30.0,
        help="無操作時に EdgeSystemState を読む間隔 (秒)",
    )
    call = subparsers.add_parser(
        "call", help="常駐中の serve へコマンドを 1 行送る (BLE は張らない)"
    )
    call.add_argument("words", nargs="+", help="shell と同じコマンド")
    call.add_argument("--socket", type=Path, default=DEFAULT_SOCKET_PATH)

    subparsers.add_parser(
        "reconnect",
        help="保存済み session で再接続だけ試す (Opcode 3 → [4] → 8 → 10)",
    )
    # --- 外部 Wi-Fi (STA)。Maintenance Mode は不要 -----------------------
    subparsers.add_parser(
        "wifi-status",
        parents=[fresh_option],
        help="外部Wi-Fi(STA)の設定と接続中APを読む (0x0500/1, 0x0500/6)",
    )
    wifi_scan = subparsers.add_parser(
        "wifi-scan",
        parents=[fresh_option],
        help="本体が見ている周辺APを列挙する (0x0500/5)",
    )
    wifi_scan.add_argument(
        "--page", type=int, help="ページ番号 (1始まり)。未指定なら全ページ"
    )
    wifi_saved = subparsers.add_parser(
        "wifi-saved",
        parents=[fresh_option],
        help="本体に登録済みのAPを列挙する (0x0500/4)",
    )
    wifi_saved.add_argument(
        "--page", type=int, help="ページ番号 (1始まり)。未指定なら全ページ"
    )
    subparsers.add_parser(
        "wifi-on", parents=[fresh_option], help="STA を ON にする (0x0500/2)"
    )
    subparsers.add_parser(
        "wifi-off", parents=[fresh_option], help="STA を OFF にする (0x0500/2)"
    )
    wifi_connect = subparsers.add_parser(
        "wifi-connect",
        parents=[fresh_option],
        help="外部Wi-Fiへ接続させる (0x0500/2 → 0x0500/9)",
    )
    wifi_connect.add_argument("ssid", help="接続先の SSID")
    wifi_connect.add_argument(
        "--security",
        choices=sorted(STA_SECURITY_INPUT),
        default="wpa1-wpa2",
        help="暗号方式 (既定: wpa1-wpa2 = WPA2パーソナル)",
    )
    wifi_connect.add_argument(
        "--password",
        help="事前共有鍵。未指定なら NP1_WIFI_PASSWORD か非表示プロンプト",
    )
    wifi_forget = subparsers.add_parser(
        "wifi-forget",
        parents=[fresh_option],
        help="登録済みAPを1件削除する (0x0500/7)",
    )
    wifi_forget.add_argument("ssid")
    wifi_forget.add_argument(
        "--security", choices=sorted(STA_SECURITY_INPUT), default="wpa1-wpa2"
    )

    subparsers.add_parser("scan", help="NP1 の広告をスキャンして表示する")
    unbond = subparsers.add_parser(
        "unbond", help="保存済み bond を消す (Linux は bluetoothctl remove)"
    )
    unbond.add_argument("--address", help="BD アドレス。未指定なら session から")
    subparsers.add_parser(
        "mode", parents=[fresh_option],
        help="現在の MaintenanceMode を照会する (0xE000/5)")
    subparsers.add_parser(
        "exit", parents=[fresh_option], help="移行フローを打ち切る (0xE000/3)")

    serial_status = subparsers.add_parser(
        "serial-status",
        parents=[entry_options],
        help="シリアルポートの現在設定を読む (0xF00D/1)",
    )
    serial_console = subparsers.add_parser(
        "serial-console",
        parents=[entry_options],
        help="シリアルコンソール入力を切り替える (0xF00D/3)",
    )
    serial_console.add_argument("status", choices=("on", "off"))
    serial_log = subparsers.add_parser(
        "serial-log",
        parents=[entry_options],
        help="デバッグシリアルログ出力を切り替える (0xF00D/2)",
    )
    serial_log.add_argument("status", choices=("on", "off"))
    for sub in (serial_status, serial_console, serial_log):
        sub.add_argument(
            "--fresh",
            action="store_true",
            help="先に新規ペアリングを行い、同じ接続のまま実行する",
        )
        sub.add_argument(
            "--enter",
            action="store_true",
            help="同じ接続内で先に Maintenance Mode へ移行する",
        )

    return parser


async def async_main(args: argparse.Namespace) -> int:
    # call は BLE を張らない。常駐している serve へ繋ぐだけ。
    if args.command == "call":
        return await _call(args)
    transport = make_transport(args, log=log)
    log(f"[*] transport = {transport.kind}")
    try:
        if args.command == "scan":
            found = await transport.scan(args.scan_timeout)
            if not found:
                log("[!] NP1 を検出できませんでした")
                return 1
            for entry in found:
                log(
                    f"[+] {entry.address} type={entry.addr_type} "
                    f"rssi={entry.rssi} name={entry.name}"
                )
            return 0
        if args.command == "unbond":
            # BlueZ は bluetoothctl remove に BD アドレスが要る
            ble = load_session(args.session).get("ble")
            address = args.address or (
                ble.get("ble_address") if isinstance(ble, dict) else None
            )
            await transport.unbond(address)
            return 0
        if args.command == "pair":
            return await command_pair(transport, args, run_maintenance=False)
        return await command_enter(transport, args)
    finally:
        with suppress(Exception):
            await transport.close()


def main() -> int:
    global VERBOSE
    parser = build_parser()
    args = parser.parse_args()
    VERBOSE = args.verbose
    if not sys.platform.startswith("linux"):
        print("[!] Linux + BlueZ が必要です", file=sys.stderr)
        return 1
    # enter 以外のサブコマンドには enter 固有の属性が無いので補う
    for name, default in (
        ("fresh", False),
        ("mode_password", "poseidon-on"),
        ("password", None),
        ("skip_start", False),
        ("keep_open", False),
        ("enter", False),
        ("status", None),
        ("no_verify", False),
    ):
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        return asyncio.run(async_main(args))
    except Np1Error as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1
    except GATT_ERRORS as error:
        print(f"[!] BLE エラー: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[*] 中断しました", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
