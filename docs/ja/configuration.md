# 設定

[English](../en/configuration.md)

tenant-pass は 1 つの JSON ファイル（`-config`）を読み込みます。完全な例は [examples/config.example.json](../../examples/config.example.json) にあります。

## ルール

- **厳格なパース。** 未知のキー、重複したキー、後続データはエラーになります。タイプミスによって設定が黙って無効になることはありません。
- **ファイルにシークレットを書かない。** シークレットはすべて、別ファイルへのパス（`*_file`）で指定します。シークレットファイルは通常のファイルでなければならず、グループやその他のユーザーが書き込めてはならず、さらに **tenant-pass を実行しているユーザーまたは root が所有している** 必要があります（他のユーザーは、モードに関係なく自分が所有するファイルを書き換えられるためです）。グループやその他のユーザーが読み取れる場合は警告がログに出力されます。末尾の改行は 1 つだけ取り除かれます。
- **信頼に関わるファイルも対象。** 公開鍵、CA バンドル、証明書、JWKS ファイル、および設定ファイル自体は、何を信頼するかを決めるものなので、同じ完全性チェック（モードと所有者）が適用されます。ただし、読み取り可能であることについての警告は出ません。
- **起動時に検証。** サーバーが起動する前にすべてがチェックされます。エラーが 1 つでもあれば起動は中止され、すべてのエラーがまとめて報告されます。`tenant-pass check-config -config FILE` は同じチェックを実行し、`-connect` を付けるとディレクトリとすべてのノードへの接続も行います。
- **設定ファイル自体** も、グループやその他のユーザーが書き込めてはなりません。
- **期間** は Go の duration 文字列です: `"30s"`、`"15m"`、`"1h"`。
- **安全でないモードには 2 つのスイッチが必要。** 平文の HTTP や平文のストア接続には、その項目自体の `insecure_plaintext*` 設定 **と**、トップレベルの `allow_insecure_plaintext: true` の両方が必要です。テスト専用です。

## トップレベル

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `listen` | `":8443"` | 待ち受けアドレス。 |
| `tls` | 必須 | サーバーの TLS。後述。 |
| `insecure_plaintext_http` | `false` | 平文の HTTP で提供する。`allow_insecure_plaintext` が必要。`tls` とは併用できません。 |
| `allow_insecure_plaintext` | `false` | あらゆる平文設定に対する全体のオプトイン。本番環境では決して使わないでください。 |
| `gateway_keys` | 必須 | 信頼するゲートウェイの公開鍵。 |
| `pass` | | パス検証の設定。 |
| `apps` | 必須 | API の呼び出しを許可するアプリケーション。 |
| `directory` | 必須 | テナントディレクトリ: `static` と `sql` のちょうど一方。 |
| `rotation` | 必須 | ローテーション鍵とタイミング。 |
| `kms` | | 鍵管理システムへの接続（[kms.md](kms.md)）。 |
| `job_tickets` | | ジョブチケット（[jobs.md](jobs.md)）。 |
| `nodes` | 必須 | tenant-pass が管理するストア。 |
| `limits` | | リクエストの制限。 |
| `shutdown` | | グレースフルシャットダウンのタイミング。 |
| `log_level` | `"info"` | `debug`、`info`、`warn`、`error`。 |

## `tls`

| キー | 説明 |
| --- | --- |
| `cert_file` | サーバー証明書チェーン（PEM）。 |
| `key_file` | サーバーの秘密鍵（PEM）。シークレットファイルのルールが適用されます。 |
| `client_ca_file` | 任意。クライアント証明書用の CA バンドル。`apps[].client_cert_uri` を有効にします。証明書は提示された場合に検証されます。証明書を必須とするかどうかはアプリケーションごとに決まります。 |

最低バージョンは TLS 1.2 です。Go のデフォルトの暗号スイートが適用されます（既知の弱いスイートは含まれません）。

## `gateway_keys[]`

| キー | 説明 |
| --- | --- |
| `id` | 鍵 ID。パスのフッターの `kid` です。`^[a-z][a-z0-9_-]{0,62}$`。 |
| `public_key_file` | Ed25519 公開鍵。PEM の `PUBLIC KEY`（PKIX）。`tenant-pass gen-gateway-key` で作成します。 |

複数の鍵を同時に設定できます（複数のゲートウェイ、またはローテーションのため）。

## `pass`

| キー | デフォルト | 範囲 | 説明 |
| --- | --- | --- | --- |
| `max_ttl` | `"60s"` | 1s〜5m | パスの `exp − iat` の最大値。 |
| `leeway` | `"5s"` | 0〜30s | `iat` について許容する時計のずれ。`exp` には決して適用されません。明示的に `"0s"` を指定すると、許容幅なしになります。 |

## `apps[]`

| キー | 説明 |
| --- | --- |
| `name` | アプリケーション名。ゲートウェイがこのアプリケーション向けに署名するパスの `aud` と一致しなければなりません。`^[a-z][a-z0-9_-]{0,62}$`。 |
| `token_sha256` | アプリトークンの SHA-256。小文字の 16 進 64 文字。`tenant-pass gen-app-token` で作成します。 |
| `client_cert_uri` | アプリケーションのクライアント証明書が持っていなければならない URI SAN（たとえば SPIFFE ID）。`tls.client_ca_file` が必要です。 |
| `jobs` | 任意。このアプリケーションでジョブチケットを有効にします: `issue`（bool。`POST /v1/job-tickets` を呼び出してよい）、`max_ttl`（デフォルト `1h`、1m〜24h。発行されるチケットの上限）、`max_tenants_per_minute`（デフォルト 60。チケットの引き換えにおける 1 分あたりの異なるテナントの数、レプリカごと。`limits.max_tenants_per_minute` に **加えて** 適用される枠）、`trusted_issuers`（このアプリケーションがチケットを引き換えてよい、`job_tickets.trusted_issuers` の ID）。`max_ttl` を超える寿命のチケットは、引き換え時にも拒否されます。`jobs` がない場合、アプリケーションはチケットを入手することも引き換えることもできません。 |

`token_sha256` / `client_cert_uri` の少なくとも一方が必要です。両方を設定した場合は、すべてのリクエストで両方が必要になります。トークンハッシュと証明書 URI は一意でなければなりません。

## `directory`

### `directory.static`

```json
"directory": {"static": {"tenants": [
  {"id": "acme", "hosts": ["acme.example.com"], "node": "pg1", "account": "t_acme", "enabled": true, "apps": ["billing"]}
]}}
```

| キー | 説明 |
| --- | --- |
| `id` | テナント ID。`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`。一意。 |
| `hosts` | このテナントが提供する正規化済みホスト名。各ホストは 1 つのテナントにしか属せません。 |
| `node` | `nodes[].name` のいずれか。 |
| `account` | そのノード上のアカウント名。 |
| `enabled` | `false` の場合、認証情報の発行を拒否します（`403 denied`）。 |
| `apps` | このテナントの認証情報の取得を許可するアプリケーション。必須で、空にはできません。 |

### `directory.sql`

テナント情報をすでに持っている PostgreSQL または MySQL データベースに対して、利用者が用意したクエリを実行します。

```json
"directory": {"sql": {
  "driver": "postgres",
  "endpoint": {"address": "central-db.internal:5432", "user": "tenant_pass_reader", "password_file": "/run/secrets/directory_pw", "database": "control"},
  "by_host":   "SELECT t.id AS tenant_id, t.node, t.role AS account, t.status = 'active' AS enabled FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id WHERE d.domain = $1 AND d.verified AND t.app = $2",
  "by_tenant": "SELECT id AS tenant_id, node, role AS account, status = 'active' AS enabled FROM tenants WHERE id = $1 AND app = $2"
}}
```

| キー | 説明 |
| --- | --- |
| `driver` | `postgres` または `mysql`。 |
| `endpoint` | 接続。[エンドポイント](#エンドポイント) を参照してください。必要な列に対する `SELECT` だけを持つ読み取り専用のアカウントを使ってください。 |
| `by_host` | `host` を持つパス用のクエリ。パラメーター: `$1`/`?` = ホスト名、`$2`/`?` = アプリケーション名。 |
| `by_tenant` | `tenant` を持つパス用のクエリ。パラメーター: テナント ID、アプリケーション名。 |

ディレクトリは、各アカウントを高々 1 つのテナントに対応付けなければなりません（2 つの行や、同じサーバーを指す 2 つのノード名が 1 つのアカウントを指していても、tenant-pass はそれを検出できません）。

各クエリは、**ちょうど** `tenant_id`、`node`、`account`、`enabled` の列（この順序、この名前で。`AS` を使ってください）を返し、行数は 0 または 1 でなければなりません。2 行以上はエラーです（フェイルクローズ）。クエリは **読み取り専用トランザクション** 内で実行されます。両方のクエリは起動時にダミーのキーで 1 回ずつ実行され、パースできることと正しい列を返すことがチェックされます。

テナントをアプリケーションごとに制限するのは、2 番目のパラメーターを使ったクエリの役割です。すべてのアプリケーションがすべてのテナントにアクセスしてよいのであれば、たとえば `AND $2::text IS NOT NULL` のように、そのことを明示してください。

## `rotation`

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `window` | `"15m"` | ウィンドウの長さ。秒単位（小数なし）、1m〜24h。 |
| `renew_before` | `"5m"` | 残り時間がこの値以下になったら次のウィンドウを払い出す。0 < `renew_before` ≤ `window`/2。 |
| `sweep_interval` | `"30s"` | MySQL と Redis のノードで期限切れのパスワードをスイープする間隔。5s ≤ `sweep_interval` ≤ `renew_before`。 |
| `max_clock_skew` | `"10s"` | レプリカの時計とストアサーバーの時計の差として許容する最大値。これを超えると書き込みは拒否されます（`clock_skew`）。1s ≤ `max_clock_skew` ≤ `renew_before`/4。 |
| `keys` | 必須 | ローテーション鍵。 |

`rotation.keys[]`:

| キー | 説明 |
| --- | --- |
| `id` | 鍵 ID（`^[a-z][a-z0-9_-]{0,62}$`）。導出の入力の一部です。鍵の名前を変えると、その鍵のすべてのパスワードが変わります。 |
| `secret_file` | 32 バイト以上のランダムなバイト列の Base64。`tenant-pass gen-rotation-key` で作成します。明らかなプレースホルダー値（繰り返しパターン）は拒否されます。 |
| `transit` | `secret_file` の代わりに: Vault/OpenBao 内の `{"key": "<Transit hmac key>", "version": N}`（`kms.vault` が必要）。バージョンは固定されます。 |
| `not_before` | RFC 3339 形式の時刻。ウィンドウ `n` では、`not_before ≤ Start(n)` を満たす鍵のうち `not_before` が最も新しいものを使います。起動時点で、最も古い鍵は少なくとも 1 ウィンドウ分過去になければなりません。 |

すべてのレプリカで、`rotation` の設定とノード名が同一でなければなりません。`window` を変更すると、すべてのアカウントのウィンドウ境界が変わります。[operations.md](operations.md#ウィンドウの変更) を参照してください。

## `nodes[]`

| キー | 種類 | 説明 |
| --- | --- | --- |
| `name` | すべて | ノード名。ディレクトリから参照されます。導出の入力の一部です。 |
| `type` | すべて | `postgres`、`mysql`、`redis` のいずれか。 |
| `endpoint` | postgres、mysql | 管理者接続。 |
| `servers` | redis | ACL ユーザーを保持する **すべての** サーバー（プライマリ、レプリカ、すべてのクラスターノード）への管理者接続。 |
| `account_pattern` | すべて | 必須。管理対象のアカウント名が一致しなければならない正規表現（Go の RE2 構文）。`^…$` の形で書く必要があり、選択（alternation）によってアンカーの外に抜け出せないよう、常に `^(?:…)$` としてコンパイルされます。管理者アカウントが使っていないプレフィックスを選んでください。たとえば `^t_[a-z0-9_]{1,40}$`。 |
| `managed_group` | postgres | 必須。すべての管理対象ロールがメンバーでなければならないロール。 |
| `managed_role` | mysql | 必須。すべての管理対象アカウントに付与されていなければならないロール。 |
| `managed_role_host` | mysql | `managed_role` のホスト部分。デフォルトは `%`。 |
| `account_host` | mysql | 管理対象アカウントのホスト部分。デフォルトは `%`。 |
| `acl_save` | redis | 変更後に `ACL SAVE` を実行する（aclfile を使うサーバー向け）。 |
| `managed_marker` | redis | ユーザーを管理対象としてマークするチャネルパターン（ユーザーはルール `&<marker>` を持っていなければなりません）。デフォルトは `tenant-pass:managed`。 |
| `max_conns` | postgres、mysql | 管理者接続プールのサイズ。デフォルトは 4。 |
| `connect` | すべて | クライアントが受け取る接続先: `host`、`port`、`database`（Redis にはなし）。通常は PgBouncer などのプーラー/プロキシを指定します。 |

管理者アカウントに必要な権限については、各ストアガイドを参照してください: [PostgreSQL](stores/postgres.md)、[MySQL](stores/mysql.md)、[Redis](stores/redis.md)。

## エンドポイント

`directory.sql.endpoint`、`nodes[].endpoint`、`nodes[].servers[]` で使われます。tenant-pass はドライバーの接続文字列（DSN）を受け付けません。DSN の安全でないデフォルト値や環境変数の参照は、構造上回避されています。

| キー | 説明 |
| --- | --- |
| `address` | `host:port`。 |
| `user` | ログイン名。 |
| `password_file` | パスワードを含むファイル。 |
| `database` | データベース名。**PostgreSQL のノードでは必須**: tenant-pass 専用のデータベースで、PUBLIC もどの管理対象ロールも接続できてはなりません（[PostgreSQL](stores/postgres.md) を参照）。PostgreSQL/MySQL のディレクトリでも使われます。 |
| `tls.ca_file` | サーバーを検証するための CA バンドル。デフォルトはシステムのルート証明書。 |
| `tls.server_name` | サーバー証明書と照合する名前。デフォルトは `address` のホスト部分。 |
| `tls.cert_file`、`tls.key_file` | 接続に使うクライアント証明書（任意）。 |
| `insecure_plaintext` | TLS を無効にする。トップレベルの `allow_insecure_plaintext` が必要。テスト専用。 |

TLS では常に証明書チェーンとホスト名が検証されます。「検証をスキップ」するオプションはありません。

## `kms`

```json
"kms": {"vault": {"address": "https://vault.internal:8200", "token_file": "/run/vault/token", "mount": "transit", "tls": {"ca_file": "/etc/tenant-pass/vault-ca.pem"}}}
```

| キー | 説明 |
| --- | --- |
| `vault.address` | ベース URL。`insecure_plaintext`（トップレベルの `allow_insecure_plaintext` と併用。テスト専用）でない限り `https`。 |
| `vault.token_file` | Vault トークンのファイル。リクエストのたびに読み直されます。 |
| `vault.namespace` | 任意の `X-Vault-Namespace`。 |
| `vault.mount` | Transit のマウント。デフォルトは `transit`。 |
| `vault.tls` | エンドポイントと同じ。 |

## `job_tickets`

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `signing_key` | | tenant-pass 自身のチケット用の鍵: `id` と、`private_key_file`（PEM、`tenant-pass gen-signing-key`）または `transit`（`key`、`version`）のいずれか。`POST /v1/job-tickets` に必要です。 |
| `trusted_issuers` | | 外部の発行者（スケジューラー）: `[{"id", "public_key_file"}]`。 |
| `max_ttl` | `"1h"` | 受け付けるチケットの寿命の最大値（1m〜24h）。 |

`signing_key` / `trusted_issuers` の少なくとも一方が必要です。鍵 ID **と鍵マテリアル** は、互いに異なり、かつ `gateway_keys` とも異なっていなければなりません（Transit の署名鍵は起動時にチェックされます）。

## `limits`

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `max_tenants_per_minute` | `60` | アプリケーションごと、1 分あたりの異なるテナントの数（レプリカごと）。 |
| `issue_timeout` | `"5s"` | ディレクトリのルックアップとストアの更新を合わせた時間の上限（100ms〜1m）。 |
| `max_concurrent_requests` | `256` | レプリカごとの処理中の認証情報リクエスト数。超過分には `503 busy` が返ります。 |

## `shutdown`

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `drain` | `"5s"` | SIGTERM の後、リスナーを閉じる前に、この時間だけ `/readyz` が 503 を返します。これによりロードバランサーがルーティングを止めます。 |
| `timeout` | `"10s"` | その後、処理中のリクエストを最大でこの時間だけ待ちます。 |

オーケストレーターの停止猶予期間は `drain + timeout` より長く設定してください（たとえばデフォルト値なら 20 秒。Docker のデフォルトの 10 秒では短すぎます）。
