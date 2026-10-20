# NP1 の fastboot

NP1（内部モデル `KX204/JP`）には fastboot を実装したブートローダーがあります。この文書は、FW `6.000600` から `7.000010` へ移行した調査個体での USB 実測と、同個体の ABL／XBL の解析結果をまとめたものです。別の個体や版で同じロック状態になるとは限りません。

## fastboot とは

fastboot は、通常の Linux が起動する前にブートローダーが USB 経由で受け付ける操作です。NP1 の通常起動中に USB デバイスが列挙されなかった構成でも、fastboot に入るとホスト側に `18d1:d00d` として列挙されました。BLE のペアリングや Maintenance Mode とは別の経路です。

## 入り方と確認

1. NP1 の microUSB を PC または Raspberry Pi に接続する。
2. NP1 の電源を切る。
3. **音量 −（Volume Down）を押しながら電源を入れ、5〜10 秒保持する。**
4. ホスト側で次を実行する。

```sh
fastboot devices
fastboot getvar unlocked
fastboot getvar secure
fastboot getvar current-slot
fastboot oem device-info
```

2026-09-21 の実機では `fastboot devices` に機器が表示され、`unlocked: no`、`secure: yes`、`current-slot: b` を読み取りました。`oem device-info` は `Device unlocked: false`、`Device critical unlocked: false`、`Verity mode: true` を返しました。これらは測定時の値です。ABL のキー処理でも `SCAN_DOWN`（値 `2`）が `BootIntoFastboot` を立てる分岐を確認しています。

fastboot から通常起動に戻すには、接続中に `fastboot continue` を送ります。`fastboot reboot-bootloader` はブートローダーへ再起動するコマンドで、同個体で受理されました。

## ロック状態と使える操作

この個体ではブートローダーがロックされ、`flashing get_unlock_ability` は `0` でした。実機で `fastboot boot <image>` は `Fastboot boot command is not available in locked device`、`fastboot flash devinfo <image>` は `Flashing is not allowed in Lock State` で拒否されました。ABL のコマンド処理でも、`flash`、`erase`、`set_active`、`boot` はロック判定を通ります。`getvar` と `oem device-info` は状態を読むために使えます。

ここでいう `download:` はホストから一時データを受信する fastboot プロトコルの操作であり、ロック中にそのデータを起動・書き込みできることを意味しません。ロック状態を確かめる目的なら、上の `getvar` と `oem device-info` だけで足ります。

### `devinfo` とロック状態の違い

2026-09-27 に通常起動した Linux から GPT の `devinfo` パーティションを読むと、アンロックを示すように見える `01 01` がありました。しかし、2026-09-21 の fastboot 応答は `unlocked=no` でした。後続の ABL／XBL 解析では、この secure 構成のブートローダーが GPT の `devinfo` ではなく、Verified Boot／Keymaster 経由の RPMB 側の device state を使う経路を確認しました。GPT の値だけでアンロック済みとは判断できません。GPT への書き込みは実施していません。

## 古い解析メモからの訂正

| 論点 | 後続の確認結果 |
|---|---|
| 大きな fastboot 転送 | 一部の入力でリセットや無応答を実測したが、コマンドは 64 byte に切り詰められ、`download:` は実際に確保したバッファ長を検査する。宣言 4096 byte のデータ転送では 4096 byte だけ受け取り、残りは受理されなかった。この ABL に、当初疑ったコマンドバッファ溢れは確認されていない。 |
| `oem select-display-panel` | ロック中にコマンド自体は受理される。しかし、その値をカーネルコマンドラインへ渡すとした初期の仮説は、XBL 全ロード領域の後続解析で撤回された。設定値がコマンドラインへ出ることは確認されていない。 |
| `fastboot boot` | ABL にコマンドは存在するが、この個体のロック状態では拒否された。コマンドの存在と実行可能性は別である。 |

上記の訂正は、この個体・解析対象バイナリに対する結果です。大きな転送によるリセット後、BLE ペアリングが失われた実機記録もあるため、状態確認には読み取りコマンドを使ってください。
