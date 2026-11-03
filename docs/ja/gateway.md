# tenant-pass-gateway

[English](../en/gateway.md)

`tenant-pass-gateway` は、すぐに使えるゲートウェイコンポーネントです。リバースプロキシに **forward-auth** サービスとして組み込み、要求されたホストのテナントについてエンドユーザーが有効なセッションを持つリクエストに対してのみ、パスに署名します。既存のコンポーネントにパスの発行を組み込みたい場合は、[gateway-integration.md](gateway-integration.md) でルールを確認してください。

```
browser ──▶ proxy (Caddy / nginx / Traefik / Envoy)
              │ 1. strip client-supplied Tenant-Pass
              │ 2. ask tenant-pass-gateway (headers only)
              │      ├─ host → route → app, tenant
              │      ├─ session JWT → verify with your IdP's JWKS
              │      ├─ tenant ∈ token's tenant claim?
              │      └─ 200 + Tenant-Pass: v4.public…   (or 200 without, or 403)
              │ 3. copy Tenant-Pass onto the request
              ▼
          application ──pass──▶ tenant-pass
```

このいずれにおいても、アプリケーションが信頼されることはありません。アプリケーションはパスを受け取りますが、パスを作成することはできません。

## 判定

| 状況 | レスポンス | パス |
| --- | --- | --- |
| 有効なセッションがあり、ホストのテナント ∈ テナントクレーム | `200` | あり |
| 別のテナントに対する有効なセッション | `403` | なし（プロキシがリクエストを拒否する） |
| セッションがない / 無効 / 期限切れ | `200`（デフォルトの `pass_through`）または `401`（`deny`） | なし |
| ホストがどのルートにも一致しない | `200` | なし |
| Host ヘッダーの形式が不正、または曖昧 | `400` | なし |
| `caller_secret_file` が設定されていて、ヘッダーがない/誤っている | `401` | なし |

`pass_through` の場合、セッションのないリクエストもアプリケーションに届くため、アプリケーションはログインページを表示できます。パスがなければテナントの認証情報は取得できないので、これは安全です。

## セッショントークン

ゲートウェイは、利用者の ID プロバイダーが発行した JWT（OIDC の ID トークン、アクセストークン、または利用者のログインサービスが発行するセッション JWT）を検証します。

- 署名はプロバイダーの **JWKS**（HTTPS 経由の `jwks_url`、または `jwks_file`）で検証し、鍵は `kid` で選択します。
- 非対称アルゴリズムのみ（デフォルトでは `RS256`、`ES256`、`EdDSA`。`HS*` と `none` は決して受け付けません）。JWK が `alg` を固定している場合、トークンはそれを使っていなければなりません。
- `iss` は `identity.issuer` と等しくなければなりません。`aud` は `identity.audiences` のいずれかを含んでいなければなりません。`exp` は必須です。`nbf` と `iat` は考慮されます。`max_token_age` は任意です。
- テナントクレーム（`identity.tenant_claim`。ドット区切りのパスも使えます）は、文字列または文字列の配列です。
- 任意の `identity.forward_claims`: パスと一緒にヘッダーで返すクレーム。アプリケーションがトークンを見なくて済むようにします（下記）。
- 任意の `identity.required_claims`: 完全に一致しなければならない文字列クレーム（たとえば `{"azp": "web-app"}` や `{"typ": "Bearer"}`）。これにより、他のクライアント向けや他の目的で発行されたトークン（アクセストークンが期待される場所での ID トークンなど）が、オーディエンスが重なるという理由だけで受け付けられることを防ぎます。

トークンは `Authorization: Bearer`（`authorization_header` が true の場合）から、次に `identity.cookie` という名前の Cookie から読み取られます。

JWKS の扱い: 使われるのは `kid` を持つ署名用の公開鍵だけです。`kid` が重複している鍵は破棄されます。URL のソースは、バックグラウンドで 10 分ごとに、また未知の `kid` に遭遇したときは最大で 30 秒に 1 回、更新されます。更新は、それを引き起こしたクライアントによってキャンセルされることはありません。**1 時間** の間 1 回も更新に成功しなかった場合、ゲートウェイは古い鍵を信頼するのをやめ、すべてのトークンを拒否します（フェイルクローズ）。これにより、更新が失敗している間に、プロバイダーが失効させた鍵が信頼されたままになることはありません。

## ルート

```json
"routes": [
  {"host": "{tenant}.billing.example.com", "app": "billing"},
  {"host": "shop.acme-corp.com",           "app": "billing", "tenant": "acme"},
  {"host": "app.example.com",              "app": "crm",     "tenant_from_token": true}
]
```

| 形式 | テナントの取得元 | チェック |
| --- | --- | --- |
| 1 つのラベル全体としての `{tenant}` | ホストのラベル | ラベル ∈ トークンのテナント |
| 完全一致のホスト + `tenant` | 設定（カスタムドメイン） | そのテナント ∈ トークンのテナント |
| 完全一致のホスト + `tenant_from_token` | トークン | トークンがちょうど 1 つのテナントを記載している |

完全一致のホストはパターンより優先されます。`{tenant}` はちょうど 1 つのラベルに一致します。`x.acme.billing.example.com` は `{tenant}.billing.example.com` に一致しません。

ホストは `request.host_header`（デフォルトは `X-Forwarded-Host`。Envoy の ext_authz では `Host` を使ってください）から読み取られ、小文字に変換され、ポートと末尾のドットが取り除かれた後、正規化済みのホスト名でなければなりません。非 ASCII の入力は、小文字への変換の前に拒否されます（Unicode のケースフォールディングによって、一部の文字が ASCII の英字に変わってしまうためです）。ホストのリスト（`a, b`）や繰り返されたヘッダー行は拒否されます。プロキシは、クライアントが送ったヘッダーに追記するのではなく、ヘッダーを **設定する** ように構成してください。

パスには常に **テナント ID**（`tenant` クレーム）が記載され、`aud` はルートの `app` になります。

## 設定

```json
{
  "listen": "127.0.0.1:9180",
  "insecure_plaintext_http": true,
  "caller_secret_file": "/run/secrets/gateway-caller-secret",

  "signing_key": {"id": "gw-2026-11", "private_key_file": "/run/secrets/gateway.key"},

  "identity": {
    "issuer": "https://login.example.com/",
    "audiences": ["tenant-apps"],
    "jwks_url": "https://login.example.com/.well-known/jwks.json",
    "algorithms": ["RS256", "ES256", "EdDSA"],
    "authorization_header": true,
    "cookie": "session",
    "tenant_claim": "tenant_id",
    "leeway": "30s",
    "cookie_fetch_metadata": "enforce"
  },
  "routes": [{"host": "{tenant}.billing.example.com", "app": "billing"}],
  "unauthenticated": "pass_through",
  "pass": {"ttl": "30s", "header": "Tenant-Pass"},
  "request": {"host_header": "X-Forwarded-Host"},
  "log_level": "info"
}
```

| キー | デフォルト | 説明 |
| --- | --- | --- |
| `listen` | `127.0.0.1:9180` | 待ち受けアドレス。 |
| `tls` | | `cert_file`、`key_file`。`client_ca_file` を設定するとクライアント証明書が **必須** になり、その場合は `client_uris` と `client_dns_names` の一方または両方でプロキシを指定しなければなりません。CA が発行した証明書は、その SAN のいずれかが一致する場合にだけ受け入れられます（サービスメッシュでは、アプリケーションを含むすべてのワークロードが同じ CA の証明書を持っています）。 |
| `max_concurrent_requests` | `256` | 処理中の認可リクエストの上限。超過したリクエストには `503` が返ります。 |
| `identity.leeway` | `30s` | `exp`/`nbf`/`iat` に対する時計の許容誤差（0–5m。`"0s"` は許容なし）。 |
| `identity.single_tenant_tokens` | `false` | テナントクレームがちょうど 1 つのテナントを指すことを要求します（「テナントのホストをまたぐ Cookie セッション」を参照）。 |
| `identity.cookie_fetch_metadata` | `enforce` | Cookie のトークンに対する Fetch Metadata チェック: `enforce` または `off`。 |
| `allow_insecure_plaintext` | `false` | テスト専用: ループバック以外での平文の設定を許可します。 |
| `log_level` | `info` | `debug`、`info`、`warn`、`error`。 |
| `health_listen` | | `GET /healthz` 用の任意のアドレス。フォワード認証のリスナーはすべてのパスを認可リクエストとして扱うため、ヘルスチェック用のパスを持ちません。 |
| `insecure_plaintext_http` | `false` | 平文の HTTP。ループバックアドレス上（プロキシの隣のサイドカー）では許可されます。それ以外では `allow_insecure_plaintext` が必要です（テスト専用）。 |
| `caller_secret_file` | | 設定した場合、呼び出し元はこの値を `Tenant-Pass-Gateway-Secret` で送らなければなりません（16 文字以上）。`listen` がループバック以外の場合は、`caller_secret_file` または `tls.client_ca_file` が**必須**です。 |
| `kms.vault` | | Vault/OpenBao への接続。[kms.md](kms.md) を参照してください。 |
| `signing_key` | 必須 | `id`（パスの `kid`）と、`private_key_file`（PEM）または `transit`（`key`、`version`）のいずれか。 |
| `identity.*` | | 上記を参照してください。`jwks_tls`（`ca_file` など）はプライベートな IdP の CA 用です。`max_token_age` は、`iat` がそれより古いトークンを拒否します。 |
| `routes` | 必須 | 上記を参照してください。 |
| `unauthenticated` | `pass_through` | または `deny`。 |
| `pass.ttl` | `30s` | 5 秒〜5 分。tenant-pass の `pass.max_ttl` を超えてはなりません。 |
| `pass.header` | `Tenant-Pass` | パスを運ぶレスポンスヘッダー。 |
| `request.host_header` | `X-Forwarded-Host` | 元のホストを運ぶヘッダー。 |

コマンド: `tenant-pass-gateway serve -config FILE`、`tenant-pass-gateway check-config -config FILE`。

tenant-pass 側では、ゲートウェイの公開鍵を同じ `id` で `gateway_keys` に追加してください（`tenant-pass gen-gateway-key` でローカルの鍵ペアを作成できます。Transit については [kms.md](kms.md#公開鍵) を参照してください）。

## プロキシの設定

プロキシは、ゲートウェイを呼び出す前にクライアントが送った `Tenant-Pass` ヘッダーをすべて取り除き、その後でゲートウェイのヘッダーをコピーしなければ **なりません**。そうしないと、セッションを持たないクライアントが自分の（盗んだ）パスをアプリケーションに送れてしまいます。

### Caddy（テスト済み）

```caddyfile
*.billing.example.com {
	# route{} keeps the written order. Caddy's default directive order
	# runs forward_auth before request_header, which would delete the
	# pass the gateway just added.
	route {
		request_header -Tenant-Pass
		forward_auth 127.0.0.1:9180 {
			uri /
			header_up Tenant-Pass-Gateway-Secret {env.TP_GATEWAY_SECRET}
			copy_headers Tenant-Pass
		}
		reverse_proxy billing:8080
	}
}
```

### nginx（テスト済み）

```nginx
location = /_tenant_pass_auth {
    internal;
    proxy_pass http://127.0.0.1:9180/;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Uri $request_uri;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Cookie $http_cookie;
    include /etc/nginx/tenant-pass-secret.conf;   # proxy_set_header Tenant-Pass-Gateway-Secret "..."; (mode 0600)
}

location / {
    auth_request /_tenant_pass_auth;
    auth_request_set $tenant_pass $upstream_http_tenant_pass;
    # Always set: an empty value removes any client-supplied header.
    proxy_set_header Tenant-Pass $tenant_pass;
    proxy_set_header X-Forwarded-Host $host;   # never pass on a client-supplied value
    proxy_pass http://billing:8080;
}
```

### Traefik

Traefik の ForwardAuth は、認可リクエストだけにヘッダーを追加することができません（headers ミドルウェアを使うとアプリケーションにも送られてしまいます）。そのため、Traefik では `caller_secret_file` を安全に使えません。ループバック以外では mTLS を使ってください。クライアント証明書を設定した `forwardAuth.tls` と、ゲートウェイ側の `client_ca_file` および `client_uris`/`client_dns_names` です。

```yaml
http:
  middlewares:
    strip-pass:
      headers:
        customRequestHeaders:
          Tenant-Pass: ""          # removes the client's header
          Tenant-Pass-User: ""     # and every forward_claims header
    tenant-pass:
      forwardAuth:
        address: http://127.0.0.1:9180/
        authResponseHeaders: ["Tenant-Pass", "Tenant-Pass-User"]
        authRequestHeaders: ["Authorization", "Cookie", "X-Forwarded-Host", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User"]
  routers:
    billing:
      rule: HostRegexp(`^[a-z0-9-]+\.billing\.example\.com$`)
      middlewares: [strip-pass, tenant-pass]
      service: billing
```

### Envoy（ext_authz、HTTP）

`request.host_header` を `Host` に設定してください。ext_authz フィルターでは、`allowed_headers` で `authorization`、`cookie`、`sec-fetch-site`、`sec-fetch-mode`、`sec-fetch-user` を許可し、`allowed_upstream_headers` に `tenant-pass`（およびすべての `forward_claims` のヘッダー）を追加してください。

クライアントが送った `tenant-pass` と ID のヘッダーは、ext_authz フィルターが実行される **前に** 取り除いてください。HTTP フィルターチェーンで ext_authz より前に header-mutation フィルターを置いて行います。ルートの `request_headers_to_remove` は使わないでください。これは ext_authz の後に適用されるため、ゲートウェイのパスまで取り除いてしまいます。また、コネクションマネージャーで `headers_with_underscores_action: REJECT_REQUEST` を設定し、アンダースコアをダッシュに正規化するアプリケーションに `tenant_pass` が届かないようにしてください。

本番運用を始める前にプロキシを検証してください。セッションが **なく**、偽造した `Tenant-Pass` ヘッダーが **ある** リクエストは、そのヘッダーを持たない状態でアプリケーションに届かなければなりません。

どのプロキシでも、アプリケーションへのリクエストには `X-Forwarded-Host` を **設定** してください（クライアントが送った値をそのまま渡してはなりません）。また、アプリケーションはテナントを認証情報のレスポンス（`tenant`）からだけ取得し、決してホストヘッダーから取得しないようにしてください。

## セッショントークンをアプリケーションに渡さない

侵害されたアプリケーションによるセッショントークンのリプレイを防ぐ最も確実な方法は、そもそもトークンを渡さないことです。`identity.forward_claims` を設定すると、ゲートウェイは検証済みのクレームを（パスと一緒の場合だけ）ヘッダーで返し、プロキシはトークンの代わりにそれを転送します。

```json
"identity": { "...": "...", "forward_claims": {"Tenant-Pass-User": "sub"} }
```

```caddyfile
route {
	request_header -Tenant-Pass
	request_header -Tenant-Pass-User
	forward_auth 127.0.0.1:9180 {
		uri /
		copy_headers Tenant-Pass Tenant-Pass-User
	}
	# The application gets the user ID, never the session token.
	request_header -Authorization
	reverse_proxy billing:8080
}
```

（Caddy 2 で検証済みです。アプリケーションはパスと `Tenant-Pass-User` を受け取り、`Authorization` は受け取りません。クライアントが送った `Tenant-Pass-User` ヘッダーは取り除かれます。）

`sub` のような、プロバイダーが管理する安定した識別子を転送してください。`email` など、ユーザーが変更できる（または未検証の可能性がある）クレームを ID として転送しないでください。ただし、`required_claims` で `email_verified` も要求する場合は除きます。

決まり: 転送するクレームは、印字可能な ASCII の文字列（256 バイト以下）でなければなりません。存在しない、または安全でない場合、そのトークンは無効として扱われ、パスは発行されません。`Authorization`、`Cookie`、`Host` などのヘッダー名は拒否されます。`Tenant-Pass` と同様に、**転送するすべてのヘッダー名を、プロキシでクライアントのリクエストから取り除いてください**。

Cookie によるセッションの場合は、ID プロバイダーのセッション専用の Cookie を使い、プロキシでそれを取り除いてください（nginx: `$http_cookie` を書き換える。Caddy: 正規表現で置換する `request_header`）。こうすると、アプリケーションは自身の Cookie を使い続けられますが、IdP のセッションは見えません。

## テナントのホストをまたぐ Cookie セッション

1 つのアプリケーションが多数のテナントのホストを提供し、ユーザーのセッション Cookie がそのすべてに送られる場合（`Domain=.billing.example.com` を持つ Cookie）、侵害されたアプリケーションは、ユーザーのブラウザーに **他の** テナントのホストを訪問させ、ユーザーが属するテナントごとにパスを集めることができます。それらを埋め込む（画像、iframe）、それらを経由してリダイレクトする、またはそれらへナビゲートすることが可能です。そうしたリクエストはすべて、プロキシを経由して同じ侵害されたアプリケーションに届きます。

**これを防ぐ境界は、リクエストヘッダーではなく、セッションのスコープです:**

1. **ホスト限定のセッション Cookie。** セッション Cookie をテナントのホストごとに、`Domain` 属性なしで発行してください。できれば `__Host-` プレフィックスを付けます（`Set-Cookie: __Host-session=…; Secure; Path=/; HttpOnly; SameSite=Lax`）。そうすればブラウザーは acme のセッションを `acme.billing.example.com` にだけ送り、他のテナントのホストへの訪問にはセッションがまったく付きません。
2. **単一テナントのトークン。** `identity.single_tenant_tokens: true` を設定し、ログインサービスにテナントごとに 1 つのトークン（ちょうど 1 つのテナントを指すテナントクレーム）を発行させてください。そうすれば、ブラウザーに何をさせても、acme のトークンから他のテナントのパスが得られることはありません。

この場合、複数のテナントに属するユーザーは、テナントのホストごとにログイン（またはシングルサインオンを利用）します。テナントがアプリケーションを共有するデプロイでは、両方の対策を使ってください。

**Fetch Metadata（多層防御）。** `identity.cookie_fetch_metadata: "enforce"`（デフォルト）の場合、**Cookie** から得たトークンは、ブラウザーの Fetch Metadata ヘッダーが、同一オリジンのリクエスト（`Sec-Fetch-Site: same-origin`）、アドレスの入力またはブックマーク（`none`）、またはユーザーが起動したトップレベルのナビゲーション（`Sec-Fetch-Mode: navigate` かつ `Sec-Fetch-User: ?1`）を示す場合にだけ使われます。Fetch Metadata のないリクエストにはパスが発行されません。これにより、受動的なホスト間リクエスト（他のテナントのホストを指す `<img>`）は阻止されます。これは侵害されたアプリケーションに対する境界では **ありません**。そのアプリケーションは他のテナントのページも提供しているからです。アプリケーションはそれらのページをフレームに入れたりそこへナビゲートしたりして、同一オリジンのリクエストを発生させることができ、ユーザーによる起動はリダイレクトを経ても維持されます。プロキシは `Sec-Fetch-*` ヘッダーをゲートウェイに渡さなければなりません（Caddy と nginx はデフォルトで渡します。Traefik と Envoy については上記を参照してください）。`"off"` は、Cookie を使うブラウザー以外のクライアントの場合にだけ設定してください。

`Authorization` ヘッダーのトークンには影響しません（ブラウザーはこれを自動的には送りません）。セッション名の Cookie が複数ある場合は、セッションがないものとして扱われます（そうしないと、兄弟ホストから投げ込まれた Cookie によって、ユーザーが攻撃者のセッションにログインさせられる可能性があります）。

## 残存リスク

- **複数テナントのセッション。** セッションがテナントごとにスコープされていない限り（上記のホスト限定の Cookie と `single_tenant_tokens`）、侵害されたアプリケーションは、ユーザーのセッションが有効な間、そのユーザーのテナントクレームに含まれるすべてのテナントのパスを入手できます。見たことのあるトークンをリプレイする方法と、ユーザーのブラウザーに他のテナントのホストを訪問させる方法です。`forward_claims` とトークンの除去でリプレイの経路はなくなります。呼び出し元の認証（ループバック以外では必須）はゲートウェイの直接呼び出しを防ぎ、Fetch Metadata は受動的なホスト間リクエストを防ぎます。ブラウザーの経路を完全に塞げるのは、セッションのスコープだけです。
- **KMS への負荷。** Transit の署名鍵を使う場合、認証されたリクエストごとに Vault の署名操作が 1 回発生します。それに応じて Vault の規模を決め、必要であればプロキシでレート制限してください。

## デプロイ

- プロキシの隣（同じホストまたはポッド）でループバック上で実行するか、TLS と `client_ca_file` または `caller_secret_file` を使って内部ネットワーク上で実行してください。
- アプリケーションがゲートウェイに到達できてはなりません。到達できると、任意の `X-Forwarded-Host` を指定してパスを要求できてしまいます。ただし、その場合でも、そのテナントに対する有効なユーザーセッションは必要です。
- 署名鍵はここ（または Vault Transit）にのみ置いてください。tenant-pass が必要とするのは公開鍵だけです。
- ゲートウェイは判定ごとに 1 行の JSON（`host`、`app`、`tenant`、`result`、`reason`）をログに出力し、トークンやパスを決してログに記録しません。
