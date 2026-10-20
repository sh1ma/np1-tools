#!/usr/bin/env python3
"""NP1 との GATT をやり取りするトランスポート層。

Linux の BlueZ を bleak 経由で使う。``pair()`` で SMP ペアリングを行う。
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Any

NP1_SERVICE = "62cedda5-df79-7f22-516f-f2ee110f7830"
EDGE_SYSTEM_STATE = "62cedda5-df79-7f22-516f-f2ee110f7831"
CONTROL_POINT = "62cedda5-df79-7f22-516f-f2ee110f7833"
DATA_SOURCE = "62cedda5-df79-7f22-516f-f2ee110f7835"
NOTIFICATION_SOURCE = "62cedda5-df79-7f22-516f-f2ee110f7837"
SECURE_CONTROL_POINT = "e0ef4e02-811e-f8aa-514a-dbda5f5fafc3"
SECURE_DATA_SOURCE = "e0ef4e02-811e-f8aa-514a-dbda5f5fafc5"
SECURE_NOTIFICATION_SOURCE = "e0ef4e02-811e-f8aa-514a-dbda5f5fafc7"

NOTIFY_CHARACTERISTICS = (
    EDGE_SYSTEM_STATE,
    DATA_SOURCE,
    NOTIFICATION_SOURCE,
    SECURE_DATA_SOURCE,
    SECURE_NOTIFICATION_SOURCE,
)


class TransportError(RuntimeError):
    """トランスポート層で継続できない場合の例外。"""


@dataclass
class Found:
    """スキャンで見つかった NP1。"""

    address: str
    name: str | None
    rssi: int
    addr_type: int = 0
    handle: Any = None  # bleak の BLEDevice など、実装固有の識別子


# ---------------------------------------------------------------------------
# Linux / BlueZ
# ---------------------------------------------------------------------------


class BleakTransport:
    """bleak を直接使うトランスポート。

    Linux の BlueZ で ``pair()`` により SMP ペアリングを行う。
    """

    kind = "bleak"

    def __init__(self, gatt_timeout: float = 30.0, log=print) -> None:
        if not sys.platform.startswith("linux"):
            raise TransportError("Linux + BlueZ が必要です")
        from bleak import BleakClient  # 遅延 import

        self._BleakClient = BleakClient
        self.gatt_timeout = gatt_timeout
        self.log = log
        self.client = None
        self.data_queue: asyncio.Queue = asyncio.Queue()

    async def scan(self, timeout: float, address: str | None = None,
                   name: str | None = None) -> list[Found]:
        from bleak import BleakScanner

        results: dict[str, Found] = {}

        def callback(device, advertisement):
            uuids = [u.lower() for u in (advertisement.service_uuids or [])]
            if NP1_SERVICE not in uuids:
                return
            if advertisement.rssi <= -70:
                return
            results[device.address] = Found(
                address=device.address,
                name=advertisement.local_name,
                rssi=advertisement.rssi,
                handle=device,
            )

        async with BleakScanner(callback):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                for found in results.values():
                    if address and found.address.upper() != address.upper():
                        continue
                    if name and not address and found.name != name:
                        continue
                    return [found]
                await asyncio.sleep(0.2)
        return list(results.values())

    async def connect(self, found: Found, pair: bool = False) -> None:
        """GATT を張る。

        ``pair=True`` で接続前にペアリングする。アプリは通常ペアリングで
        ``createBond()`` を呼び、以後 bond 済みの機器にしか繋がない
        (``ed/i.java``)。BlueZ では SMP が走る。
        """
        self.client = self._BleakClient(
            found.handle or found.address,
            timeout=self.gatt_timeout,
            pair=pair,
        )
        await self.client.connect()

    async def subscribe_all(self) -> None:
        for characteristic in NOTIFY_CHARACTERISTICS:
            await self.client.start_notify(
                characteristic,
                lambda _sender, payload, source=characteristic: (
                    self.data_queue.put_nowait((source, bytes(payload)))
                ),
            )

    async def read(self, characteristic: str) -> bytes:
        return bytes(await self.client.read_gatt_char(characteristic))

    async def write(self, characteristic: str, payload: bytes) -> None:
        await self.client.write_gatt_char(characteristic, payload, response=True)

    async def disconnect(self) -> None:
        if self.client is not None and self.client.is_connected:
            with suppress(Exception):
                await self.client.disconnect()

    @property
    def is_connected(self) -> bool:
        return self.client is not None and self.client.is_connected

    async def ensure_bond(self) -> bool:
        """アプリの ``BluetoothDevice.createBond()`` に相当する処理を試みる。

        APK は通常ペアリングで、FW 5.0001 以上なら bond を必須にしている
        (``ed/i.java`` の ``getBondState() == BOND_BONDED`` 判定)。
        以後の再接続も bond 済み機器しか対象にしない。

        BlueZ の ``pair()`` の成否を返す。
        """
        try:
            await self.client.pair()
            self.log("[+] pair() が成功しました")
            return True
        except Exception as error:  # noqa: BLE001
            self.log(f"[!] BlueZ pair() に失敗しました: {type(error).__name__}: {error}")
            return False

    async def unbond(self, address: str | None = None) -> None:
        if not address:
            raise TransportError("unbond には BD アドレスが要ります")
        result = subprocess.run(
            ["bluetoothctl", "remove", address],
            capture_output=True,
            text=True,
        )
        self.log(f"[*] bluetoothctl remove {address}: {result.stdout.strip()}")
        if result.returncode != 0:
            raise TransportError(f"bond を消せませんでした: {result.stderr.strip()}")

    async def close(self) -> None:
        await self.disconnect()
def gatt_error_types() -> tuple:
    """再試行して良い bleak の例外型。"""
    from bleak.exc import BleakError

    return (BleakError,)


def make_transport(args, log=print):
    """BLE トランスポートを作る。"""
    return BleakTransport(gatt_timeout=args.gatt_timeout, log=log)
