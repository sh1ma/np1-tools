# NP1 tools

[NP1 の構成、ペアリング、Maintenance Mode、SD ログ保存](docs/np1-overview.md)

[fastboot の入り方とロック状態](docs/fastboot.md)

Raspberry Pi から Bluetooth LE 経由で NP1 を操作する Linux + BlueZ 専用スクリプトです。`np1_maint.py` がペアリング、再接続、機器操作、常駐サーバーを担当し、`np1_transport.py` が BlueZ と BLE GATT を扱います。`tools/np1_wifi_raw.py` は、接続中の対話シェルに貼る Wi-Fi 設定コマンドを生成します。

プロトコルと実機で確認した操作手順は [NP1 の構成と Bluetooth 操作](docs/np1-overview.md) にまとめています。

## 準備

Linux、BlueZ、Python 3.13 と `bleak` を使います。Raspberry Pi 上の Debian 13、BlueZ 5.82、Python 3.13.5 で再接続した実機記録があります。

```sh
python3 -m venv .venv
.venv/bin/python -m pip install bleak
```

NP1 は BR/EDR と LE の両方を広告します。BlueZ が BR/EDR 側へ接続するのを防ぐため、アダプタを LE 専用にした実機手順があります。

```sh
sudo btmgmt power off
sudo btmgmt bredr off
sudo btmgmt power on
```

## 操作

初回は NP1 本体を通常ペアリング待受にしてから実行します。`serve` は接続を保持し、`call` はそのプロセスへ UNIX ソケット経由で指示を送ります。

```sh
.venv/bin/python -u np1_maint.py --response-timeout 120 serve --fresh
```

別のターミナルから操作します。

```sh
.venv/bin/python np1_maint.py call status
.venv/bin/python np1_maint.py call wifi-scan
.venv/bin/python np1_maint.py call volume
.venv/bin/python np1_maint.py call quit
```

2 回目以降は保存済みのセッションと BlueZ の bond を使います。

```sh
.venv/bin/python -u np1_maint.py --response-timeout 120 serve
```

セッションは Linux では `$XDG_STATE_HOME/np1/session.json`、未指定なら `~/.local/state/np1/session.json` に保存されます。認証情報を含むため、公開リポジトリへ追加しないでください。利用できるコマンドと引数は `np1_maint.py --help` で確認できます。
