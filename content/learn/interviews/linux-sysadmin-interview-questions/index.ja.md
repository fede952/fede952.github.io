---
title: "Linux SysAdmin面接：プロセス、パーミッション＆ネットワーキング"
description: "シニアSysAdminおよびDevOpsロール向けのLinuxシステム管理面接の必須質問20選。ファイルパーミッション、プロセス管理、systemd、ネットワーキング、トラブルシューティングをカバー。"
date: 2026-02-11
tags: ["linux", "interview", "sysadmin", "devops"]
keywords: ["linux interview questions", "red hat interview", "bash scripting questions", "linux permissions interview", "sysadmin interview questions", "linux process management", "systemd interview", "linux networking questions", "senior linux engineer", "rhcsa exam prep"]
draft: false
schema_json: >
  {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    "name": "Linux SysAdmin面接：プロセス、パーミッション＆ネットワーキング",
    "description": "パーミッション、プロセス、systemd、ネットワーキングに関するLinuxシステム管理面接の必須質問20選。",
    "proficiencyLevel": "Advanced",
    "inLanguage": "ja"
  }
---

## システム初期化

Linuxシステム管理は、現代のインフラストラクチャの基盤です。SysAdmin、DevOps、SRE、クラウドエンジニアのいずれのロールに面接する場合でも、ユーザー管理、プロセスのトラブルシューティング、ネットワーク設定、サーバーのセキュリティ確保など、すべてコマンドラインから行う能力が試されます。このガイドでは、シニア候補者をジュニアから区別する20の質問を、実際の運用経験を示す回答とともに取り上げます。

**コマンドのクイックリファレンスが必要ですか？** 準備中は[Linux SysAdminチートシート](/cheatsheets/linux-sysadmin-permissions/)を開いておきましょう。

---

## ファイルパーミッションと所有権

<details>
<summary><strong>1. Linuxのパーミッションモデル（rwx、8進数表記、特殊ビット）を説明してください。</strong></summary>
<br>

すべてのファイルには3つのパーミッション層があります：**所有者**、**グループ**、**その他**。各層は**読み取り（r=4）**、**書き込み（w=2）**、**実行（x=1）**を持つことができます。

8進数表記はこれらを組み合わせます：`chmod 755` = rwxr-xr-x（所有者：フル、グループ/その他：読み取り+実行）。

**特殊ビット**：
- **SUID（4000）**：ファイルは実行するユーザーではなく、ファイルの所有者として実行されます。例：`/usr/bin/passwd`はrootとして実行され、ユーザーが自分のパスワードを変更できるようにします。
- **SGID（2000）**：ファイルではグループ所有者として実行されます。ディレクトリでは、新しいファイルがディレクトリのグループを継承します。
- **Sticky bit（1000）**：ディレクトリでは、ファイルの所有者のみが自分のファイルを削除できます。典型的な例：`/tmp`。
</details>

<details>
<summary><strong>2. ハードリンクとソフトリンクの違いは何ですか？</strong></summary>
<br>

- **ハードリンク**：inode（ディスク上の実際のデータ）への直接参照。同じファイルへの複数のハードリンクは同じinode番号を共有します。1つのハードリンクを削除しても他には影響しません — すべてのハードリンクが削除されるまでデータは存続します。ファイルシステムの境界を越えることはできません。ディレクトリにリンクすることはできません。
- **ソフトリンク（シンボリックリンク）**：ファイルパスへのポインタ（ショートカットのようなもの）。独自のinodeを持ちます。ターゲットファイルが削除されると、シンボリックリンクはダングリングリンクになります。ファイルシステムを越えることができます。ディレクトリにリンクすることができます。

`ls -li`を使用してinode番号を確認し、ハードリンクの関係を確認します。
</details>

<details>
<summary><strong>3. 開発者が共有ディレクトリに書き込めません。どのように診断し修正しますか？</strong></summary>
<br>

診断手順：
1. `ls -la /shared/` — 所有権とパーミッションを確認。
2. `id developer` — ユーザーが属するグループを確認。
3. `getfacl /shared/` — 標準パーミッションを上書きする可能性のあるACLを確認。

一般的な修正方法：
- ユーザーをディレクトリのグループに追加：`sudo usermod -aG devteam developer`。
- ディレクトリにSGIDを設定して新しいファイルがグループを継承するようにする：`chmod g+s /shared/`。
- ACLが必要な場合：`setfacl -m u:developer:rwx /shared/`。
- umaskがグループ書き込みをブロックしていないことを確認（`umask`コマンドで確認）。
</details>

<details>
<summary><strong>4. umaskとは何で、ファイル作成にどのように影響しますか？</strong></summary>
<br>

`umask`は、新しいファイルとディレクトリから**削除される**デフォルトのパーミッションを定義します。最大パーミッションから差し引かれるビットマスクです。

- ファイルのデフォルト最大値：666（デフォルトで実行権限なし）。
- ディレクトリのデフォルト最大値：777。
- `umask 022`の場合：ファイルは644（rw-r--r--）、ディレクトリは755（rwxr-xr-x）を取得。
- `umask 077`の場合：ファイルは600（rw-------）、ディレクトリは700（rwx------）を取得。

システム全体では`/etc/profile`で、ユーザーごとでは`~/.bashrc`で設定。セキュリティにとって重要 — 緩いumaskは機密ファイルを未認証ユーザーに公開する可能性があります。
</details>

## プロセス管理

<details>
<summary><strong>5. プロセス、スレッド、デーモンの違いを説明してください。</strong></summary>
<br>

- **プロセス**：独自のメモリ空間、PID、ファイルディスクリプタ、環境を持つ実行中のプログラムのインスタンス。`fork()`または`exec()`によって作成されます。
- **スレッド**：プロセス内の軽量な実行単位。スレッドは同じメモリ空間とファイルディスクリプタを共有しますが、独自のスタックとレジスタを持ちます。プロセスよりも高速に作成できます。
- **デーモン**：制御端末なしで動作するバックグラウンドプロセス。通常はブート時に起動され、継続的に実行され、サービスを提供します（sshd、nginx、cron）。慣例的に`d`サフィックスで命名されます。
</details>

<details>
<summary><strong>6. ゾンビプロセスとは何で、どのように対処しますか？</strong></summary>
<br>

**ゾンビ**は、実行を終了したが、親プロセスが`wait()`を呼び出して終了ステータスを読み取っていないため、まだプロセステーブルにエントリがあるプロセスです。PIDスロット以外のリソースは消費しません。

ゾンビの特定：`ps aux | grep Z` — ステータス`Z`（defunct）を表示します。

ゾンビを**kill することはできません** — すでに死んでいます。削除するには：
1. 親プロセスに`SIGCHLD`を送信：`kill -s SIGCHLD <parent_pid>`。
2. 親が無視する場合、親プロセスをkillするとゾンビは孤児になり、`init`（PID 1）に引き取られます。Initは自動的に`wait()`を呼び出してクリーンアップします。

大量のゾンビは通常、子プロセスを回収していないバグのある親プロセスを示します。
</details>

<details>
<summary><strong>7. Linuxシグナルを説明してください。SIGTERM、SIGKILL、SIGHUPとは何ですか？</strong></summary>
<br>

シグナルはプロセスに送信されるソフトウェア割り込みです：

- **SIGTERM（15）**：丁寧な終了要求。プロセスはこれをキャッチし、リソースをクリーンアップし、正常に終了できます。`kill <pid>`がデフォルトで送信するものです。
- **SIGKILL（9）**：強制終了。キャッチ、ブロック、無視することはできません。カーネルがプロセスを即座に終了します。最後の手段としてのみ使用 — クリーンアップは不可能です。
- **SIGHUP（1）**：歴史的に「ハングアップ」。多くのデーモン（nginx、Apache）はSIGHUPを受信すると、再起動の代わりに設定をリロードします。
- **SIGINT（2）**：割り込み、Ctrl+Cで送信されます。
- **SIGSTOP/SIGCONT（19/18）**：プロセスの一時停止と再開。
</details>

<details>
<summary><strong>8. CPUを過剰に消費しているプロセスをどのように見つけて終了しますか？</strong></summary>
<br>

1. プロセスの特定：`top -o %CPU`または`ps aux --sort=-%cpu | head -10`。
2. 詳細の取得：`ls -l /proc/<pid>/exe`で実際のバイナリを確認。
3. 何をしているか確認：`strace -p <pid>`でシステムコール、`lsof -p <pid>`で開いているファイルを確認。
4. 正常停止：`kill <pid>`（SIGTERM）— クリーンアップを許可。
5. 強制停止：`kill -9 <pid>`（SIGKILL）— SIGTERMが失敗した場合のみ。
6. 再発防止：systemdで管理されている場合、サービスのunitファイルに`CPUQuota=50%`を設定。
</details>

## Systemdとサービス

<details>
<summary><strong>9. systemdとは何で、SysVinitとどう違いますか？</strong></summary>
<br>

**SysVinit**：`/etc/init.d/`のシェルスクリプトを使用した順次起動プロセス。サービスは定義されたランレベルで順番に起動します。起動時間が遅い。シンプルだが依存関係の処理が限定的。

**systemd**：unitファイルを使用した並列起動プロセス。依存関係、ソケットアクティベーション、オンデマンドサービス起動、リソース制御のためのcgroups、ロギングのためのjournaldをサポート。はるかに高速な起動。サービス、タイマー、マウント、ソケット、ターゲットを管理。

systemdはRHEL、Ubuntu、Debian、Fedora、SUSE、Archのデフォルトinitシステムです。
</details>

<details>
<summary><strong>10. カスタムsystemdサービスを作成する方法は？</strong></summary>
<br>

`/etc/systemd/system/myapp.service`にunitファイルを作成します：

```ini
[Unit]
Description=My Application
After=network.target

[Service]
Type=simple
User=deploy
WorkingDirectory=/opt/myapp
ExecStart=/opt/myapp/bin/server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

その後：`sudo systemctl daemon-reload && sudo systemctl enable --now myapp`。

`Type`の主要な値：`simple`（デフォルト、メインプロセスがフォアグラウンドで実行）、`forking`（プロセスがバックグラウンドにフォーク、`PIDFile`が必要）、`oneshot`（一度実行して終了）、`notify`（プロセスがsd_notifyを通じて準備完了を通知）。
</details>

<details>
<summary><strong>11. systemdで起動パフォーマンスを分析する方法は？</strong></summary>
<br>

- `systemd-analyze` — 合計起動時間。
- `systemd-analyze blame` — 起動時間順にソートされたサービスのリスト。
- `systemd-analyze critical-chain` — クリティカルな起動パスのツリー。
- `systemd-analyze plot > boot.svg` — 起動シーケンスのビジュアルタイムラインを生成。
- `journalctl -b -p err` — 現在の起動のエラー。

起動を高速化するには：不要なサービスを無効化（`systemctl disable`）、サービスをソケットアクティベーションに切り替え（オンデマンド起動）、blameの出力から遅いサービスを特定。
</details>

## ネットワーキング

<details>
<summary><strong>12. TCPの3ウェイハンドシェイクを説明してください。</strong></summary>
<br>

1. **SYN**：クライアントが初期シーケンス番号を含むSYNパケットをサーバーに送信。
2. **SYN-ACK**：サーバーがSYN-ACKで応答し、クライアントのSYNを確認し、自身のシーケンス番号を送信。
3. **ACK**：クライアントがサーバーのシーケンス番号を確認するACKを送信。接続が確立。

切断は4ウェイハンドシェイクを使用：FIN → ACK → FIN → ACK（各側が独立して接続の半分を閉じる）。

デバッグ：`ss -tuln`（リスニングポート）、`ss -tulnp`（プロセス名付き）、`tcpdump -i eth0 port 80`（パケットキャプチャ）。
</details>

<details>
<summary><strong>13. TCPとUDPの違いは何ですか？</strong></summary>
<br>

- **TCP**（Transmission Control Protocol）：コネクション型、信頼性あり、順序保証された配信。ハンドシェイク、確認応答、再送信を使用。オーバーヘッドが高い。HTTP、SSH、FTP、データベースに使用。
- **UDP**（User Datagram Protocol）：コネクションレス、信頼性なし、順序保証なし。ハンドシェイクなし、確認応答なし。オーバーヘッドが低い、レイテンシが低い。DNS、DHCP、VoIP、ストリーミング、ゲームに使用。

重要なポイント：「信頼性なし」は悪いという意味ではありません — アプリケーションが必要に応じて信頼性を処理するという意味です。DNSはUDPを使用します。クエリが小さく高速だからです。応答が失われた場合、クライアントは単に再送信します。
</details>

<details>
<summary><strong>14. サーバーが外部IPに到達できません。どのようにトラブルシューティングしますか？</strong></summary>
<br>

レイヤーごとのアプローチ：
1. **L1 - 物理層**：`ip link show` — インターフェースは起動していますか？
2. **L2 - データリンク層**：`ip neighbor show` — ARPテーブルは充填されていますか？
3. **L3 - ネットワーク層**：`ip route show` — デフォルトゲートウェイはありますか？`ping <gateway>` — 到達できますか？
4. **L3 - 外部**：`ping 8.8.8.8` — IPでインターネットに到達できますか？
5. **L7 - DNS**：`nslookup google.com` — DNS解決は機能していますか？`/etc/resolv.conf`を確認。
6. **ファイアウォール**：`iptables -L -n`または`nft list ruleset` — アウトバウンド接続はブロックされていますか？
7. **ルートトレース**：`traceroute 8.8.8.8` — どこでパスが途切れていますか？
</details>

## ストレージとファイルシステム

<details>
<summary><strong>15. inodeとは何ですか？</strong></summary>
<br>

inodeは、ファイルに関するメタデータを格納するデータ構造です：パーミッション、所有権、サイズ、タイムスタンプ、ディスク上のデータブロックへのポインタ。すべてのファイルとディレクトリにinodeがあります。

重要なのは、**ファイル名はinodeに格納されない**ということです — ディレクトリエントリに格納され、名前をinode番号にマッピングします。これがハードリンクが機能する理由です：複数のディレクトリエントリが同じinodeを指すことができます。

inodeが不足すると（ディスク空き容量があっても）、新しいファイルを作成できなくなります。`df -i`で確認。一般的な原因：数百万の小さなファイル（メールキュー、キャッシュディレクトリ）。
</details>

<details>
<summary><strong>16. ダウンタイムなしでLVM論理ボリュームを拡張する方法は？</strong></summary>
<br>

1. 利用可能なスペースを確認：`vgdisplay` — 空きPE（physical extents）を探す。
2. 空きスペースがない場合、新しい物理ディスクを追加：`pvcreate /dev/sdb && vgextend myvg /dev/sdb`。
3. 論理ボリュームを拡張：`lvextend -L +10G /dev/myvg/mylv`。
4. ファイルシステムをリサイズ（ext4/XFSではオンライン）：
   - ext4：`resize2fs /dev/myvg/mylv`
   - XFS：`xfs_growfs /mountpoint`

アンマウント不要。ダウンタイムなし。これがrawパーティションに対するLVMの主要な利点の1つです。
</details>

## セキュリティとハードニング

<details>
<summary><strong>17. su、sudo、sudoersの違いは何ですか？</strong></summary>
<br>

- **su**（switch user）：別のユーザーに完全に切り替えます。`su -`はターゲットユーザーの環境をロードします。ターゲットユーザーのパスワードが必要です。
- **sudo**（superuser do）：別のユーザー（通常root）として単一のコマンドを実行します。**呼び出し元の**パスワードが必要です。誰が何を実行したかの監査ログを提供します。
- **sudoers**（`/etc/sudoers`）：誰がsudoを使用でき、どのコマンドを実行できるかを定義する設定ファイル。`visudo`（構文検証）で安全に編集します。

ベストプラクティス：直接のrootログインを無効にする（sshd_configで`PermitRootLogin no`）。代わりに管理者にsudoアクセスを付与 — 説明責任（誰が何をしたかを記録）と詳細な制御を提供します。
</details>

<details>
<summary><strong>18. SSHサーバーをハードニングする方法は？</strong></summary>
<br>

`/etc/ssh/sshd_config`の必須変更：
- `PermitRootLogin no` — 直接のrootログインを防止。
- `PasswordAuthentication no` — 鍵ベースの認証を強制。
- `PubkeyAuthentication yes` — SSHキーを有効化。
- `Port 2222` — デフォルトポートから変更（自動スキャンを削減）。
- `MaxAuthTries 3` — 認証試行を制限。
- `AllowUsers deploy admin` — 特定のユーザーをホワイトリストに登録。
- `ClientAliveInterval 300` — アイドルセッションを切断。
- `fail2ban`をインストール — ログイン失敗後にIPを自動的にバン。
</details>

## スクリプティングと自動化

<details>
<summary><strong>19. Bashにおける$?、$$、$!、$@の違いは何ですか？</strong></summary>
<br>

- **$?** — 最後のコマンドの終了ステータス（0 = 成功、非ゼロ = 失敗）。
- **$$** — 現在のシェルのPID。
- **$!** — 最後のバックグラウンドプロセスのPID。
- **$@** — スクリプトに渡されたすべての引数（各々が個別の単語として）。
- **$#** — 引数の数。
- **$0** — スクリプト自体の名前。
- **$1, $2, ...** — 個別の位置引数。

一般的なパターン：`command && echo "success" || echo "fail"`は`$?`を暗黙的に使用します。
</details>

<details>
<summary><strong>20. 過去7日間に変更された100MBを超えるすべてのファイルを見つけるワンライナーを書いてください。</strong></summary>
<br>

```bash
find / -type f -size +100M -mtime -7 -exec ls -lh {} \; 2>/dev/null
```

内訳：
- `find /` — ルートから検索。
- `-type f` — ファイルのみ（ディレクトリではない）。
- `-size +100M` — 100メガバイトより大きい。
- `-mtime -7` — 過去7日以内に変更。
- `-exec ls -lh {} \;` — 各結果の人間が読めるサイズを表示。
- `2>/dev/null` — パーミッション拒否エラーを抑制。

ソート付きの代替：`find / -type f -size +100M -mtime -7 -printf '%s %p\n' 2>/dev/null | sort -rn | head -20`。
</details>
