# NP1 の構成と Bluetooth 操作

この文書は、Pioneer NP1（内部モデル `KX204/JP`）の APK・ファームウェア解析と、所有する実機での確認記録をまとめたものです。版や個体によって異なる可能性がある事項は、確認した対象と時期を併記します。ここにない資料を読むことを前提としません。

## 製品とハードウェア

NP1 はパイオニア製のドライブレコーダーです。前方と車内・後方の 2 カメラ、録画設定、駐車監視設定を備えます。本体は Qualcomm QCS610（ARMv8 AArch64、8 コア、RAM 公称 3 GiB）を採用し、eMMC から Qualcomm Linux Embedded（Yocto/OE、systemd）を起動します。Android が動くのは操作側のスマートフォンです。

| 分類 | 確認した構成 |
|---|---|
| 撮影・音声 | 前方と車内・後方のカメラ、マイク、音声出力。純正録画仕様は両カメラとも H.264 で、前方は高画質設定で 1920×1080/27 fps、車内・後方は 1920×1080/16 fps。 |
| センサー | GNSS。SSC の実測では加速度、ジャイロ、温度、周囲光、動き検出の値を取得した。これらは取得できた種類であり、物理チップの個数や型番を示さない。 |
| 無線 | Bluetooth LE、Bluetooth Classic、Wi-Fi STA／クルマ Wi-Fi AP、LTE。LTE・GNSS には内蔵 Quectel EC25 系モジュールを使用する。 |
| 入出力・記録 | eMMC、microSD、外部 microUSB、側面の操作ボタン、ライトバー。内部の EC25 は別の USB host 系統につながる。外部端子と内部 USB コントローラーの対応は一部未確定。 |

根拠の種類: QCS610・RAM・OS・eMMC は本体ダンプと実機の device tree／`MemTotal`、センサーは FW `7.000010` 実機の SSC API 値、LTE・GNSS は EC25 の NMEA と USB 接続、BLE は My NP1 APK と実機 GATT、カメラは純正録画仕様と実機の両カメラ映像で確認したものです。

### 確認した版

実機の BLE `EdgeSystemState` から、本体ファームウェア **`6.000600`** と **`7.000010`** を別の時点に読み取りました。FW `7.000010` の OTA パッケージも取得・解析されています。これは調査個体の記録であり、全製品の最新版を示しません。解析に使用した My NP1 の Android APK は `jp.pioneer.npapp` **`1.6.3`**（versionCode `319`）です。アプリ版と本体 FW 版は別です。

## My NP1 と NP1 の通信

通常の初期設定・機器操作には Android アプリ **My NP1** を使います。アプリは NP1 の Bluetooth LE 広告をサービス UUID `62CEDDA5-DF79-7F22-516F-F2EE110F7830` で絞り、LE GATT に接続します。NP1 は Bluetooth Classic にも対応しますが、ここで扱う My NP1 の機器制御は **BLE GATT** です。

| GATT 要素 | 用途 |
|---|---|
| `62CEDDA5-…-7831` | `EdgeSystemState` の read／notify。FW 版、起動・ペアリング状態、機器番号を含む。 |
| `62CEDDA5-…-7833` / `…-7835` | 通常 ControlPoint への write／DataSource の read・notify。 |
| `E0EF4E02-…-FAFC3` / `…-FAFC5` | Secure ControlPoint への write／Secure DataSource の read・notify。 |

独自 PDU の要求は `token || timestamp(8 byte) || functionId(2 byte) || opcode(2 byte) || flag/requestId(1 byte) || protobuf payload || signature(4 byte)` です。ヘッダー内の複数バイト整数は big-endian。認証済み要求の署名は `SHA-256(secret || 署名前の PDU)[0:4]`。認証後は NP1 が発行した access token と secret を使います。ペアリング要求などの NORMAL frame は別形式の固定 token／signature を使います。

機能 ID の例は、GNSS `0x0300`、センサー `0x0301`、音量 `0x0400`、外部 Wi-Fi `0x0500`、クルマ Wi-Fi・LTE `0x0501`、録画設定 `0x0600`、FW 更新情報 `0x0900` です。Maintenance Mode の入退場は `0xE000`、診断機能は `0xF0xx` を使います。

## 通常ペアリングの流れ

My NP1 APK `1.6.3` には、用途の異なる 2 種類の認証フローがあります。

| フロー | 本体のボタン操作 | `EdgeSystemState` 条件 | OS bond と保存 |
|---|---|---|---|
| 通常ペアリング | 中央○を約 2 秒長押し | `StartupMode=0`、`Certification!=0` | FW `5.0001` 以上では bond が必要。BLE token も保存する。 |
| 取付用の一時認証 | 斜線マイクと中央○を同時に約 2 秒長押し | `StartupMode!=0`、`Certification!=0` | bond 不要。一時 token はメモリ上だけで扱い、通常ペアリングとして永続化しない。 |

以下は通常ペアリングと、このリポジトリの `np1_maint.py` がたどる流れです。

1. NP1 側面の**中央○ボタンを約 2 秒長押し**し、通常ペアリング待受にする。BLE `EdgeSystemState` で `StartupMode=0`（NORMAL）、`Certification!=0`（ACCEPTING）を確認する。
2. My NP1 は LE GATT で接続する。APK は FW `5.0001` 以上で OS の Bluetooth bond を要求する。Linux／BlueZ では `pair()` で SMP bond を作る。NP1 は dual-mode 機器なので、Pi では BlueZ アダプタを LE 専用にして接続した実績がある。
3. `functionId=0`、opcode `2` で device model を送り、NP1 から access token・refresh token・secret を受け取る。
4. opcode `8` で My NP1 アカウントの user key を送り、opcode `10` で初期化完了へ進む。user key は APK に埋め込まれておらず、ログイン結果から取得する。実機では opcode `8` の応答が空でも、後続の opcode `10` へ進んだ記録がある。
5. この CLI はセッションを `~/.local/state/np1/session.json`（`XDG_STATE_HOME` 指定時はその配下）へ権限 `0600` で保存する。新規ペアリング時は本体側の資格情報保存周期をまたぐため、接続を 65 秒維持する。

このリポジトリで初回から接続を維持する実行例です。アカウントの user key が未保存なら My NP1 のログイン情報を手元で入力します。`serve` の標準入力を使うため、最初は対話可能なターミナルで起動します。

```sh
sudo btmgmt power off
sudo btmgmt bredr off
sudo btmgmt power on
.venv/bin/python -u np1_maint.py --response-timeout 120 serve --fresh
```

ボタン操作後、別ターミナルから状態を読みます。

```sh
.venv/bin/python np1_maint.py call status
.venv/bin/python np1_maint.py call volume
```

2 回目以降は保存済み session と BlueZ の bond で `.venv/bin/python -u np1_maint.py --response-timeout 120 serve` を起動します。再接続では opcode `3` の challenge を送り、access token が期限切れなら opcode `4` で更新し、user key があれば opcode `8`／`10` へ進みます。`call` は常駐プロセスへ UNIX socket で指示を送るだけで、新しい BLE 接続は張りません。

## Maintenance Mode（POSEIDON モード） への入り方

解析対象の製品 APK では Maintenance メニューの設定値が `false` で、通常の My NP1 画面からは開けません。本体 FW の `System` にある `MaintenanceEntryExit`（Function `0xE000`）と、本リポジトリの CLI を使います。以下は FW `7.000010` 実機で POSEIDON 入場を確認した手順です。

1. 常駐接続で `.venv/bin/python np1_maint.py call mode` を実行し、現在モードを読む。未入場なら `1 (OFF)`。
2. `.venv/bin/python np1_maint.py call enter` を実行する。CLI が `0xE000/1`（StartNotify）を送る。FW 側の待受タイマーは 60 秒。
3. 60 秒以内に NP1 本体の音量ボタンを **`+ - + - - +`** の順に押す。FW のキーコード列は `[2,1,2,1,1,2]`。この +/− 対応は後日の実機操作で確認した。成功時、NP1 が `0xE000/0x8002`（CommandInputEndNotify）を通知する。
4. CLI が `0xE000/4` に `POSEIDONDBG ON` を入れたパスワード要求を送り、`0x8004` の protobuf `08 02`（mode `2`、POSEIDON）を受け取る。
5. CLI が `0xE000/5` で現在モード `2` を読み、Maintenance 専用の `0xF00D/1` も受理されることを確認する。

CLI の `call enter` はキー操作の前後に mute と音量を再確認します。FW `7.000010` の別個体では、キー列は一致したものの、パスワード送信前の mute 再設定が読み返しで失敗して `call enter` が止まった記録があります。この場合、**キー列一致後の 60 秒以内**であれば同じ接続から `.venv/bin/python np1_maint.py call raw e000 4 0a0e504f534549444f4e444247204f4e` と送って復帰できた記録があります。`0a0e...` は `POSEIDONDBG ON` の protobuf string です。直後に `call mode` で `2 (POSEIDON)` を確認します。これは実機で起きた例外時の手順であり、通常の `call enter` が成功した場合には不要です。

ボタンを押せない遠隔操作だけでは初回入場を完了できません。接続後のモードが持続する場合もあるため、毎回 `call mode` で現在値を確認します。

## SD カードへのログ一括保存

ログダンプは **`0xF00B/1`（BatchLogSave）** で NP1 の SD カードへ保存します。`serial-log on`（`0xF00D/2`）はシリアル出力の設定で、SD ログダンプとは別です。`0xF00B/1` の BLE 応答にログ本文は含まれません。

1. FAT 形式の microSD を NP1 に挿し、常駐接続で `call mode` が `2 (POSEIDON)` を返すことを確認する。
2. `.venv/bin/python np1_maint.py call raw f00b 1` を実行する。要求 payload は空。
3. `function=0xf00b opcode=0x8001 payload=0801` を確認する。protobuf field 1 の `true` であり、保存成功を意味する。`payload=(empty)` は `false` として扱う。応答待ちの timeout だけでは保存の成否は断定しない。
4. 書き込み後、取り外す前に十分時間を置く。実機では成功応答直後の取り外しで FAT の孤立クラスタが出た一方、約 74 秒待った回では検証が通った。カードを PC で読み、FAT を検証してから `LogAll_YYYYMMDDhhmmss` ディレクトリを確認する。

保存先には `application/`、`booting_journal/`、`core/`、`rw/`、`system/` などが観測されています。`System` の処理は現在ログを flush し、version file、`build.prop`、SDlog、coredump などをコピーします。SD の hotplug 後に応答が空だった実機では、カードを挿したまま NP1 を再起動した後に `0801` を得ました。再起動後は BLE 接続・認証をやり直し、再度 `call mode` を確認します。`0xF00B` は任意の本体ファイルをすべて再帰コピーする機能ではありません。

## 記録間の相違と未確定事項

| 論点 | 記録と現在の扱い |
|---|---|
| 音量キーの +/− 対応 | 初期の静的解析ではコード `1`／`2` の物理対応を未確定としていた。2026-09-20 の実機操作で `+ - + - - +` の一致を確認したため、上の手順は実測を採用した。 |
| シリアルコンソール | 初期の解析メモには `0xF00D/3` で UART ログインが開くとの記述がある。FW7 の後続調査では設定値 `login=1`／`serial=1` の保存は確認したが、物理 UART でログインできることは確認していない。ログダンプ手順には使わない。 |
| FW の表示と更新時期 | `6.000600` と `7.000010` は実機の異なる時点の `EdgeSystemState` 値。再起動後に `7.000010` を確認した記録があるが、更新がいつ、どの操作で非稼働スロットへ適用されたかは確定していない。 |
| SD 保存の成否 | 静的解析では `0xF00B` のコピー処理が見える。実機では SD hotplug 後に空応答、SD を挿したまま再起動した後に `0801` を観測した。空応答の具体的な原因は特定していない。要求送信だけで成功としない。 |

セッションには access token・refresh token・secret が含まれます。ログダンプにも機器固有情報や過去のログが含まれ得るため、この公開リポジトリには追加しません。
