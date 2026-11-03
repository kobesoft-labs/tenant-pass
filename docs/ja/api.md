# HTTP API

[English](../en/api.md)

tenant-pass は `listen` で HTTPS（TLS 1.2 以上）を提供します。すべてのレスポンスに `Cache-Control: no-store` が付きます。内部ネットワーク専用です。

## `POST /v1/credentials`

パスをテナントの認証情報と交換します。

### リクエスト

```http
POST /v1/credentials HTTP/1.1
Host: tenant-pass.internal:8443
Authorization: Bearer tpa_9b0Z…
Content-Type: application/json

{"pass": "v4.public.…", "repair": false}
```

| | |
| --- | --- |
| `Authorization` | `Bearer <app token>`。ヘッダーはちょうど 1 つ。省略してよいのは、クライアント証明書のみで認証するアプリケーションの場合だけです。 |
| クライアント証明書 | `client_cert_uri` が設定されたアプリケーションでは必須です。 |
| `Content-Type` | `application/json`（`charset` などのパラメーターは許可されます）。 |
| ボディ | 最大 4096 バイト。以下のメンバーだけを持つ JSON オブジェクト。未知のメンバーや重複したメンバーは拒否されます。 |

| メンバー | 型 | 必須 | 意味 |
| --- | --- | --- | --- |
| `pass` | string | はい | ゲートウェイから受け取ったパス。[pass-format.md](pass-format.md) を参照してください。 |
| `repair` | bool | いいえ | tenant-pass から得た認証情報がストアで拒否された（認証失敗）直後に `true` を設定します。PostgreSQL の場合、tenant-pass はロールが最新に見えても書き直します（レプリカごと、アカウントごとに 10 秒に最大 1 回。それを超えるリクエストは通常どおり処理されます）。MySQL と Redis はリクエストのたびに実際のパスワードハッシュを検証するため、`repair` による追加の効果はありません。 |

### レスポンス `200 OK`

```json
{
  "tenant": "acme",
  "store": "postgres",
  "host": "pgbouncer.internal",
  "port": 6432,
  "database": "app",
  "username": "t_acme",
  "password": "umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM",
  "expires_at": "2026-11-03T12:13:59Z",
  "refresh_at": "2026-11-03T12:08:59Z"
}
```

| メンバー | 意味 |
| --- | --- |
| `tenant` | ディレクトリが返したテナント ID。 |
| `store` | `postgres`、`mysql`、`redis` のいずれか。 |
| `host`、`port`、`database` | 接続先（`nodes[].connect`）。`database` は設定されていない場合、および Redis の場合は常に省略されます。 |
| `username` | アカウント名。 |
| `password` | base64url の 43 文字。シークレットとして扱い、プロセスのメモリ内にのみ保持してください。 |
| `expires_at` | この時刻を過ぎると、パスワードで新規接続を開けなくなる（PostgreSQL）か、次のスイープで削除される可能性があります（MySQL、Redis）。既存の接続は影響を受けません。 |
| `refresh_at` | この時刻以降に新しい認証情報を取得してください。`refresh_at` 以降、tenant-pass は次のウィンドウを払い出します。 |

同じウィンドウ内のリクエストに対しては、どのレプリカ、どのワーカーにも同じパスワードが返されます。

### エラー

ボディは常に `{"error": "<code>"}` です。理由は返されず、監査ログに記録されます。

| ステータス | `error` | 意味 |
| --- | --- | --- |
| 400 | `invalid_request` | ボディが空でない `pass` を持つ JSON オブジェクトではない、未知または重複したメンバーがある、または後続データがある。 |
| 400 | `invalid_pass` | パスが拒否された: 形式不正、未知の鍵、不正な署名、不正なクレーム、期限切れ、または `aud` が呼び出し元のアプリケーションではない。 |
| 401 | `unauthorized` | アプリケーションの認証に失敗した。`WWW-Authenticate: Bearer realm="tenant-pass"` が付きます。 |
| 403 | `denied` | そのようなテナントが存在しない、アプリケーションがそのテナントに対して許可されていない、テナントが無効化されている、またはストアがアカウントを拒否した。 |
| 404 | `not_found` | 未知のパス。 |
| 405 | `method_not_allowed` | `POST` ではない。 |
| 413 | `request_too_large` | ボディが 4096 バイトを超えている。 |
| 415 | `unsupported_media_type` | コンテンツタイプが `application/json` ではない。 |
| 429 | `rate_limited` | アプリケーションが直近 1 分間に（このレプリカ上で）`limits.max_tenants_per_minute` 個を超える異なるテナントを要求した。すでに要求済みのテナントに対する繰り返しのリクエストは制限されません。 |
| 503 | `busy` | `limits.max_concurrent_requests` に達した。バックオフしてリトライしてください。 |
| 503 | `unavailable` | ディレクトリまたはストアのエラー、タイムアウト、またはこのレプリカとストアサーバーの間の時計のずれ。バックオフしてリトライしてください（別のレプリカでは成功する可能性があります）。 |

クライアントは、400、401、403 をそのパスについては恒久的なエラーとして、429/503 をリトライ可能なエラーとして扱ってください。

## `GET /healthz`

ライブネス。プロセスが動作している間は `200 {"status":"ok"}` を返します。認証は不要です。

## `GET /readyz`

レディネス。認証は不要です。

- `200 {"status":"ready"}`: ディレクトリとすべてのノードが応答している。
- `503 {"status":"draining"}`: シャットダウンが始まっている（SIGTERM）。そのレプリカをロードバランサーから外してください。
- `503 {"status":"unavailable"}`: ディレクトリまたはいずれかのノードに到達できない。

バックエンドのチェック結果は 5 秒間キャッシュされます。

## 監査ログ

tenant-pass は、認証情報リクエストごとに 1 行の JSON を標準出力に書き出します（`"msg":"credential"`）。

```json
{"time":"2026-11-03T12:00:01Z","level":"INFO","msg":"credential","request_id":"43f007226bb0e766","app":"billing","repair":false,"jti":"hamSSKegCc-kk82SdW2dpw","host":"acme.example.com","tenant":"acme","node":"pg1","account":"t_acme","store":"postgres","window":1993007,"key_id":"k1","changed":true,"expires_at":"2026-11-03T12:13:59Z","result":"ok","duration_ms":7}
```

| フィールド | 意味 |
| --- | --- |
| `result` | `ok`、またはクライアントに返したエラーコード。 |
| `reason` | 失敗した理由: `app_auth`、`body_size`、`body_json`、`content_type`、`pass_malformed`、`pass_unknown_key`、`pass_signature`、`pass_claims`、`pass_expired`、`pass_audience`、`distinct_tenants`、`tenant_not_found`、`tenant_disabled`、`directory_error`、`directory_mismatch`、`unknown_node`、`account_refused`、`clock_skew`、`timeout`、`store_error`、`max_concurrent_requests`。 |
| `error` | `directory_error` / `store_error` / `account_refused` の場合のエラーの分類（SQLSTATE、MySQL のエラー番号、Redis のエラープレフィックス、拒否理由）。サーバーのエラーメッセージはコピーされません。 |
| `changed` | ストアが変更されたかどうか。 |
| `window`、`key_id` | 認証情報がどのウィンドウとどのローテーション鍵に属するか。 |

ログに決して記録されないもの: パスワード、ベリファイア、ハッシュ、パス、アプリトークン、ローテーション鍵。クライアントの IP アドレスは tenant-pass では記録しません。必要であればロードバランサーから取得してください。

レベル: 成功時は `INFO`、クライアントエラーは `WARN`、`directory_error`、`store_error`、`account_refused`、`clock_skew`、`unknown_node`、`directory_mismatch` は `ERROR` です。何をアラート対象にすべきかについては [operations.md](operations.md#監視) を参照してください。
