#!/usr/bin/env python3
"""すでに開いている `np1_maint.py shell` に貼るための raw コマンド列を作る。

本体を外部 Wi-Fi (STA) に繋ぐには Function 0x0500 を 2 発送る。

    0x0500/2  StaSettingChangeRequest { setting = SST_ON }
    0x0500/9  ApConnectRequest { ssid, securityType, password }

shell を起動し直せば `wifi-connect <ssid>` で済むが、本体は一度切断すると
再接続を受け付けないことが多い。**すでに繋がっている shell を使い切る**ために、
貼り付け用の行だけをここで組み立てる。

鍵が端末やチャットに残らないよう、出力はファイルへ書く (0600)。

使い方:
    .venv/bin/python tools/np1_wifi_raw.py "SSID"
    .venv/bin/python tools/np1_wifi_raw.py "SSID" --security wpa2-wpa3
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import np1_maint as m  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ssid", help="接続先の SSID")
    parser.add_argument(
        "--security",
        choices=sorted(m.STA_SECURITY_INPUT),
        default="wpa1-wpa2",
        help="暗号方式。推測せず 0x0500/5 (wifi-scan) が報告した値に合わせる"
        " (既定: wpa1-wpa2)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("/tmp/np1-wifi-cmd.txt"),
        help="貼り付け用コマンドの書き出し先 (既定: /tmp/np1-wifi-cmd.txt)",
    )
    args = parser.parse_args()

    security = m.security_type(args.security)
    if security == 1:
        password = ""
    else:
        password = os.environ.get("NP1_WIFI_PASSWORD") or getpass.getpass(
            "外部Wi-Fi password: "
        )
    payload = m.sta_connect_payload(args.ssid, security, password)

    lines = [
        "raw 0500 1",
        "raw 0500 2 " + m.protobuf_int(1, 1).hex(),
        "raw 0500 9 " + payload.hex(),
        "raw 0500 1",
        "raw 0500 6",
    ]
    args.out.write_text("\n".join(lines) + "\n")
    args.out.chmod(0o600)

    print(f"[+] {args.out} に {len(lines)} 行を書きました (payload {len(payload)} byte)")
    print("    1: STA の現在状態を読む            (0x0500/1)")
    print("    2: STA を ON にする                (0x0500/2 setting=SST_ON)")
    print("    3: SSID と鍵を渡して接続させる     (0x0500/9)  ← 鍵が入っている行")
    print("    4: STA の状態を読み直す (IP が付くはず)")
    print("    5: 接続中の AP を確認              (0x0500/6)")
    print()
    print("    np1> のシェルに 1 行ずつ貼ってください:")
    print(f"      cat {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
