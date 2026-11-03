# Redis / Valkey

[English](../../en/stores/redis.md)

## 仕組み

各テナントは Redis の ACL ユーザーです。ACL ユーザーは複数のパスワードを保持できます。tenant-pass は現在のウィンドウのパスワードと、更新中はさらに次のウィンドウのパスワードを保持します。

```
ACL SETUSER t_acme resetpass #<sha256 of password(n)> [#<sha256 of password(n+1)>]
```

- パスワードは SHA-256 ハッシュ（`#…`）で設定されるため、平文が Redis、そのスローログ、`MONITOR` に届くことはありません。
- `resetpass` は、それ以外のすべてのパスワードと `nopass` フラグを削除します。ユーザーのそれ以外の設定（コマンド、キー、チャネル、on/off）は一切変更されません。
- 更新中は両方の認証情報が使えます。
- **スイーパー**（`rotation.sweep_interval` ごと）が、ウィンドウの終了したパスワードと、tenant-pass が導出していないパスワードを削除します。1 ウィンドウの間まったく要求されなかったユーザーには、最終的にパスワードが 1 つも残らず、ログインできなくなります。

## 対応バージョン

Redis 7.0 以降と Valkey 7.2 以降（tenant-pass は `ACL DRYRUN` を必要とします）。Redis 8 でテスト済みです。

## ACL はサーバーごと

Redis は ACL をレプリケーション **しません**。プライマリとそのレプリカ、Sentinel が管理する各インスタンス、Redis Cluster の各ノードなど、すべてのサーバーがそれぞれ独自のユーザーを保持します。それらを **すべて** ノードの `servers` に列挙してください。tenant-pass はすべてのサーバーを読み取り、1 回だけ計画を立て、同じパスワードの組を各サーバーに書き込みます。状態を失ったサーバー（たとえば aclfile なしで再起動したもの）は、次のリクエストまたはスイープで元の状態に戻されます。

サーバーが `aclfile` からユーザーを読み込む場合は、`acl_save: true` を設定して、変更のたびに tenant-pass が `ACL SAVE` を実行するようにしてください。そうしないと、再起動したサーバーは、tenant-pass が修正するまで古いパスワードのまま復帰します。

## セットアップ

すべてのサーバーで（または aclfile に）、tenant-pass が使う ACL コマンドだけを持つ管理者ユーザーを作成します。

```
ACL SETUSER tenant_pass_admin on ><random> -@all +acl|getuser +acl|setuser +acl|users +acl|dryrun +acl|save +time +ping +auth +hello
```

`+acl|setuser` は強力です。権限の付与を含め、任意のユーザーを変更できます。Redis にはこれより狭い選択肢がありません。`tenant_pass_admin` の認証情報は管理者パスワードと同様に保護し、Redis へのネットワークアクセスを制限してください。

テナントユーザーは、テナントに必要なものだけと、**管理対象マーカー** `&tenant-pass:managed` を付けて作成します（プロビジョニングが行います）。

```
ACL SETUSER t_acme on resetchannels &tenant-pass:managed &t:acme:* -@all +@read +@write ~t:acme:*
```

マーカーはチャネルルールです。ユーザーが pub/sub コマンドも使える場合を除いて何の権限も与えず、使える場合でもその 1 つのチャネル名に限られます。tenant-pass は（スイーパーも含めて）マーカーを持たないユーザーには決して手を触れません。別のマーカーを使うには `managed_marker` を設定してください。

## 安全性チェック

発行の前に、すべてのサーバーで、tenant-pass は次の条件をすべて満たさない限り拒否します（監査ログに `account_refused`）。

- ユーザー名が `account_pattern` と `[A-Za-z0-9_.:-]{1,128}` に一致し、`default` ではない。
- ユーザーが存在し（tenant-pass がユーザーを作成することはありません）、管理対象マーカーを持つ。
- **`ACL DRYRUN`** により、ユーザーが次のいずれも実行できないことが報告される: `ACL …`、`CONFIG …`、`MODULE …`、`DEBUG`、`SHUTDOWN`、`FLUSHALL`、`FLUSHDB`、`SWAPDB`、`KEYS`、`CLIENT KILL/LIST/PAUSE`、`SCRIPT FLUSH`、`FUNCTION LOAD/DELETE/FLUSH`、`REPLICAOF`、`SLAVEOF`、`FAILOVER`、`CLUSTER …`、`SAVE`、`BGSAVE`、`BGREWRITEAOF`、`MONITOR`、`SYNC`、`PSYNC`、`SLOWLOG RESET`、`LATENCY RESET`、`MEMORY PURGE`。
- **`ACL DRYRUN`** により、ユーザーがランダムなキーに対する `GET`/`SET` も、ランダムなチャネルに対する `PUBLISH`/`SUBSCRIBE` もできない（つまり、キーとチャネルのパターンが制限されている）ことが報告される。
- ルール文字列の静的チェックで、`allcommands`、`allkeys`、`+@all`、`+@admin`、`+@dangerous`、または上記コマンドの明示的な許可が見つからない。
- サーバーの `TIME` が、`rotation.max_clock_skew` の範囲内でレプリカの時計と一致している。

`ACL DRYRUN` は、カテゴリやセレクターを含めた、ユーザーの *実効* 権限を評価します。これは重要です。`@slow` などのカテゴリには `ACL` や `CONFIG` が含まれているからです。テナントには個別のコマンドか、狭いカテゴリ（`@read`、`@write`、`@string`、`@hash` など）を付与してください。

スイーパーはパスワードを削除するだけなので、マーカーはチェックしますが、`DRYRUN` による検査は省略します。

## ノードの設定

```json
{
  "name": "cache1",
  "type": "redis",
  "servers": [
    {"address": "cache1-a.internal:6380", "user": "tenant_pass_admin", "password_file": "/run/secrets/cache1-admin-password", "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}},
    {"address": "cache1-b.internal:6380", "user": "tenant_pass_admin", "password_file": "/run/secrets/cache1-admin-password", "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}}
  ],
  "account_pattern": "^t_[a-z0-9_]{1,40}$",
  "acl_save": false,
  "connect": {"host": "cache1.internal", "port": 6380}
}
```

Redis で TLS を有効にし（`tls-port`、`tls-cert-file` など）、平文のポートを無効にしてください。

## 並行性

更新は冪等であり（同じウィンドウからは常に同じハッシュが得られます）、前進のみです。同じユーザーに対して 2 つのレプリカが競合した場合、最悪でも前のウィンドウのパスワードが一時的に再追加されるだけで、それはスイーパーが再び削除します。tenant-pass が導出していないパスワードが設定されることは決してありません。

## クライアント向けの注記

クライアントは `AUTH <username> <password>`（または `HELLO 3 AUTH …`）で認証します。`+ping` を持たないユーザーは、`AUTH` に成功した後の `PING` に対して `NOPERM` を受け取ります。これは認証失敗ではありません。
