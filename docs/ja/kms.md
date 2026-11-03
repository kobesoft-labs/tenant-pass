# 鍵管理（Vault / OpenBao Transit）

[English](../en/kms.md)

tenant-pass と tenant-pass-gateway は、鍵をファイルではなく鍵管理システムに保管できます。サポートしているのは、**Transit** シークレットエンジンを使う **HashiCorp Vault** と **OpenBao** です。

| 鍵 | 使用者 | Transit の鍵タイプ | 操作 |
| --- | --- | --- | --- |
| ローテーション鍵（パスワード導出） | tenant-pass | `hmac` | `transit/hmac/<key>/sha2-256` |
| ジョブチケットの署名鍵 | tenant-pass | `ed25519` | `transit/sign/<key>` |
| ゲートウェイの署名鍵 | tenant-pass-gateway | `ed25519` | `transit/sign/<key>` |

## 得られるもの

ファイルの鍵の場合、tenant-pass のホストに侵入した攻撃者はローテーション鍵をコピーでき、利用者が攻撃者を排除した後であっても、**その鍵が有効である限り、オフラインで** すべてのテナントのパスワードを導出できます。

Transit を使うと、鍵が Vault の外に出ることはありません。攻撃者が鍵を使えるのは、ホストとその Vault トークンを支配している **間だけ** です。トークンを失効させれば、攻撃者は何も導出できなくなります。Vault の監査ログには、すべての使用が記録されます。

現時点でホストを支配している攻撃者からは守れません。

## 正しさ

- **HMAC は標準のもの。** Transit の `hmac/…/sha2-256` は鍵マテリアルを使った通常の HMAC-SHA256 であるため、[導出の仕様](derivation.md) とそのテストベクターは変わりません。（エクスポートしたテスト用の鍵に対して、Transit の出力とローカルの HMAC を比較してテストしています。）
- **バージョンは固定。** 各ローテーション鍵は、Transit の鍵 **と** バージョンを指定します。パスワードはローテーション鍵が有効である間ずっと同じでなければならないため、tenant-pass は常にそのバージョンを正確に指定して要求し、それ以外のバージョンのレスポンスは拒否します。
- **署名はローカルで確認。** Transit が署名した後、tenant-pass は起動時に読み取った公開鍵でその署名を検証します。Transit の鍵の設定を誤っても、tenant-pass が検証に失敗するトークンを出力することはありません。
- **キャッシュ。** 導出した値は、アカウントとウィンドウごとにメモリ内にキャッシュされます（上限あり、期限あり）。そのため Transit が呼び出されるのは、リクエストごとではなく、アカウントごと、ウィンドウごとに約 2 回です。

## セットアップ

```sh
vault secrets enable transit
vault write -f transit/keys/tenant-pass-rotation type=hmac key_size=32
vault write -f transit/keys/tenant-pass-jobs type=ed25519
vault write -f transit/keys/tenant-pass-gateway type=ed25519
```

鍵をエクスポート可能にしないでください。

ポリシー（最小権限、コンポーネントごとに 1 つ）:

```hcl
# tenant-pass
path "transit/hmac/tenant-pass-rotation/*" { capabilities = ["update"] }
path "transit/sign/tenant-pass-jobs"       { capabilities = ["update"] }
path "transit/keys/tenant-pass-jobs"       { capabilities = ["read"] }
```

```hcl
# tenant-pass-gateway
path "transit/sign/tenant-pass-gateway" { capabilities = ["update"] }
path "transit/keys/tenant-pass-gateway" { capabilities = ["read"] }
```

認証には任意の Vault 認証方式（Kubernetes、AppRole、クラウドの IAM）を使い、トークンをファイルに書き出す **Vault Agent** またはサイドカーを経由させてください。tenant-pass はリクエストのたびにトークンファイルを読み直すため、更新されたトークンは再起動なしで反映されます。

## 設定

```json
"kms": {
  "vault": {
    "address": "https://vault.internal:8200",
    "token_file": "/run/vault/token",
    "namespace": "",
    "mount": "transit",
    "tls": {"ca_file": "/etc/tenant-pass/vault-ca.pem"}
  }
},
"rotation": {
  "keys": [
    {"id": "r-2026-11", "transit": {"key": "tenant-pass-rotation", "version": 1}, "not_before": "2026-11-01T00:00:00Z"}
  ]
},
"job_tickets": {
  "signing_key": {"id": "tp-jobs-1", "transit": {"key": "tenant-pass-jobs", "version": 1}}
}
```

| キー | 説明 |
| --- | --- |
| `address` | ベース URL。`insecure_plaintext`（とトップレベルの `allow_insecure_plaintext`。テスト専用）を設定しない限り `https` が必須です。 |
| `token_file` | Vault トークンを含むファイル。シークレットファイルのルールが適用されます。リクエストのたびに読み直されます。 |
| `namespace` | `X-Vault-Namespace` として送信されます（Vault Enterprise / HCP）。 |
| `mount` | Transit のマウントパス。デフォルトは `transit`。 |
| `tls` | `ca_file`、`server_name`、`cert_file`/`key_file`（クライアント証明書認証）。検証は常に有効です。 |

クライアントはリダイレクトに決して従わず（トークンが別の場所に送られる可能性があるため）、環境変数の HTTP プロキシも使いません。エラーで報告されるのは HTTP ステータスだけで、レスポンスボディやトークンが含まれることは決してありません。

ゲートウェイも同じ `kms.vault` ブロックと `signing_key.transit` を使います。

## Transit の鍵のローテーション

**ローテーション鍵。** `vault write -f transit/keys/tenant-pass-rotation/rotate` でバージョン 2 が作成されます。これを、ファイルの鍵の場合とまったく同じように、未来の `not_before` を持つ **新しい** ローテーション鍵として追加します（[operations.md](operations.md#ローテーション鍵のローテーション)）。

```json
{"id": "r-2026-12", "transit": {"key": "tenant-pass-rotation", "version": 2}, "not_before": "2026-12-01T03:00:00Z"}
```

古いローテーション鍵が設定から削除されるまで、バージョン 1 を Transit で利用可能なまま（`min_available_version`）にしておいてください。

**署名鍵。** Transit でローテーションした後、新しいバージョンを新しい `id` で設定し、新しい公開鍵を検証者に公開します（ゲートウェイの場合は tenant-pass の `gateway_keys`。tenant-pass 自身のジョブ用の鍵は、ジョブの検証処理が自動的に取り込みます）。古い鍵 ID は、それで署名されたパスやチケットが失効するまで信頼したままにしておいてください。

## 公開鍵

Transit に保管されたゲートウェイ鍵に対して tenant-pass の `gateway_keys` を設定するには、公開鍵を PEM に変換します。

```sh
vault read -field=keys -format=json transit/keys/tenant-pass-gateway \
  | jq -r '."1".public_key' | base64 -d > gw.raw
# Ed25519 SubjectPublicKeyInfo prefix (octal escapes work in every POSIX printf)
( printf '\060\052\060\005\006\003\053\145\160\003\041\000'; cat gw.raw ) \
  | openssl pkey -pubin -inform DER -outform PEM > gateway-2026-11.pub
```

## 可用性

Transit の鍵を使う場合、キャッシュされていないパスワードを導出するには、tenant-pass は Vault を必要とします。Vault に到達できないと、キャッシュされていないウィンドウに対するリクエストは `503 unavailable` で失敗します（監査ログでは `store_error`、エラーに `kms` が含まれます）。Vault は高可用性構成で実行し、これらのエラーに対してアラートを設定してください。
