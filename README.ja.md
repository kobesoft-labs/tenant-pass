# tenant-pass

**ゲートウェイが実際に転送したリクエストに対してのみ発行される、短命でテナント単位のデータベース認証情報。**

[English README](README.md)

tenant-pass は、テナントごとに専用のデータベースアカウント（テナントごとの PostgreSQL ロール、MySQL ユーザー、Redis ACL ユーザー）を持つマルチテナントアプリケーション向けの、小さくステートレスな認証情報ブローカーです。

アプリケーションはどのテナントのデータベースパスワードも保持しません。アプリケーションはあるテナントのリクエストを処理するとき、tenant-pass にそのテナントの認証情報を要求し、次の 2 つを提示します。

1. 自身の ID（ベアラートークンと TLS クライアント証明書のいずれか、または両方）
2. **パス（pass）**: ゲートウェイが署名した短命のトークンで、*「いま、テナント X 宛てのリクエストをあなたに転送している」* ことを示します。

tenant-pass は両方を検証し、テナントを解決し、テナントのアカウントに新しいパスワードを設定してそれを返します。パスワードは短い期間（デフォルトでは 15 分）が過ぎると自動的に失効します。

```
             request for acme.example.com
  client ───────────────────────────────▶ gateway ──── signs pass {aud: billing, host: acme.example.com, exp: +30s}
                                            │
                                            ▼ request + pass
                                      application "billing"
                                            │  POST /v1/credentials
                                            │  Authorization: Bearer <app token>
                                            │  {"pass": "v4.public..."}
                                            ▼
                                       tenant-pass ── directory: acme.example.com → node pg1, role t_acme
                                            │
                                            │  ALTER ROLE t_acme PASSWORD '<SCRAM verifier>' VALID UNTIL '…'
                                            ▼
                                     PostgreSQL / MySQL / Redis
```

## なぜ必要か

典型的なマルチテナントアプリケーションでは、アプリケーションはすべてのテナントのデータにアクセスできます。1 つの強力なアカウントで接続しているか、中央のテーブルからすべてのテナントの認証情報を復号できるかのどちらかです。アプリケーションのプロセスを乗っ取った攻撃者は、**すべてのテナントを一度に** 手に入れます。

tenant-pass を使うと、次のようになります。

- **テナントのパスワードを保存しない。** アプリケーションには、保存データとして盗めるものがありません。パスワードを導出するローテーション鍵は tenant-pass の中にしか存在しません。
- **認証情報は実際のリクエストに対してのみ。** 侵害されたアプリケーションはパスを発行できません。使えるのは、ゲートウェイが実際に送ってきたリクエストのパスだけで、しかもパスの有効期間内（数秒）に限られます。
- **1 つのアプリケーションに束縛。** パスには転送先のアプリケーション（`aud`）が記載されており、他のアプリケーションはそれを使えません。
- **被害範囲をレート制限。** 各アプリケーションが 1 分あたりに認証情報を取得できる *異なる* テナントの数は限られています。
- **有効期限はデータベースが強制。** PostgreSQL は、tenant-pass が停止していても `VALID UNTIL` 以降はそのパスワードを拒否します。MySQL と Redis にはネイティブの有効期限がないため、tenant-pass は最大 2 ウィンドウ分のパスワードだけを保持し、期限切れのものをスイープします。
- **データベースへの通信路に平文を流さない。** tenant-pass が送るのは SCRAM ベリファイア（PostgreSQL）、`caching_sha2_password` ハッシュ（MySQL）、SHA-256 ACL ハッシュ（Redis）です。パスワードがデータベースのログ、ステートメント統計、レプリケーションストリームに現れることはありません。
- **危険なアカウントは拒否。** tenant-pass は、明示的に管理対象としてマークされたアカウントだけを変更します。管理者権限やテナント横断の権限（ロールメンバーシップを通じて継承される権限を含む）を持つアカウントには、ディレクトリがそれを指していても決して手を触れません。
- **自分の時計ではなくデータベースの時計を信頼。** 書き込みの前に、各レプリカは自分の時計をストアサーバーの時計と比較します。時計が狂っているレプリカは、パスワードを未来へ押し進めるのではなく、処理を拒否します。

これは汎用のシークレットマネージャーではありません。リクエストへの束縛なしに動的な認証情報が必要であれば、HashiCorp Vault / OpenBao のデータベースシークレットエンジンを検討してください。tenant-pass が対象とするのは、より限定された 1 つのケース、すなわちマルチテナント SaaS における **リクエストに束縛された、テナント単位の** アクセスです。

## 機能

| | PostgreSQL | MySQL | Redis / Valkey |
| --- | --- | --- | --- |
| アカウント | ロール | ユーザー | ACL ユーザー |
| 対応バージョン | 13 以降（16 以降を強く推奨） | 8.0.27 以降、8.4、9.x | Redis 7.0 以降、Valkey 7.2 以降 |
| 送信するもの | SCRAM-SHA-256 ベリファイア | caching_sha2_password ハッシュ | SHA-256 ACL ハッシュ |
| 有効期限 | ハード（`VALID UNTIL`） | ソフト（デュアルパスワード + スイーパー） | ソフト（複数パスワード + スイーパー） |
| ローテーション時の重複期間 | なし（クライアントが 1 回リトライ） | 新旧どちらも有効 | 新旧どちらも有効 |
| 「管理対象」マーカー | グループロールへのメンバーシップ | マーカーロールの付与 | マーカーチャネルルール |

- **すぐに使えるゲートウェイ**: `tenant-pass-gateway` は Caddy、nginx、Traefik、Envoy に forward-auth として組み込め、利用者の ID プロバイダーのセッショントークン（JWT/OIDC）を検証し、ユーザー自身のテナントに対してのみパスに署名します。
- **バックグラウンドジョブ**: ジョブチケットにより、キューに入れられた処理やスケジュールされた処理が、パスの寿命を延ばすことなく、後から 1 つのテナントの認証情報を取得できます。
- **KMS 内の鍵**: ローテーション鍵と署名鍵を HashiCorp Vault / OpenBao Transit に保管できるため、侵害されたホストから鍵をコピーされることはありません。
- ステートレス: ロードバランサーの背後で任意の数のレプリカを実行できます。すべてのレプリカが同一のパスワードを導出します。
- テナントディレクトリ: 静的（設定ファイル内）、または PostgreSQL / MySQL 上の独自の SQL クエリ。
- パス形式: ドメイン分離を施した PASETO v4.public（Ed25519）。PASETO ライブラリがある言語であれば、どの言語でもゲートウェイを実装できます。
- 厳格な設定: 未知のキー、重複したキー、弱い鍵、検証されない TLS、誰でも書き込めるシークレットファイルは、いずれも起動時エラーになります。
- 依存関係の少ない（データベースドライバー程度）単一の静的バイナリ。

## クイックスタート

> 以下の手順は平文の接続を使っており、**ローカルでの評価専用** です。本番環境については [docs/ja/operations.md](docs/ja/operations.md) を参照してください。

```sh
go install github.com/kobesoft-labs/tenant-pass/cmd/tenant-pass@latest
go install github.com/kobesoft-labs/tenant-pass/cmd/tenant-pass-gateway@latest   # optional ready-made gateway

# Gateway key pair (the private key belongs to the gateway only)
tenant-pass gen-gateway-key -private gw.key -public gw.pub

# Rotation key (tenant-pass only)
tenant-pass gen-rotation-key -out rotation.key

# Application token: give the token to the application, put the hash in the config
tenant-pass gen-app-token
```

1 つのテナント用に PostgreSQL ロールを準備します（[詳細な手順](docs/ja/stores/postgres.md)）。

```sql
CREATE ROLE tenant_pass_admin LOGIN CREATEROLE PASSWORD '...';
CREATE ROLE tenant_pass_managed NOLOGIN;
CREATE ROLE t_acme LOGIN IN ROLE tenant_pass_managed;
GRANT t_acme TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

設定ファイルを書き（[リファレンス](docs/ja/configuration.md)、[例](examples/config.example.json)）、次を実行します。

```sh
tenant-pass check-config -config config.json -connect
tenant-pass serve -config config.json

# Act as the gateway and the application:
PASS=$(tenant-pass sign-pass -key gw.key -kid gw1 -aud billing -host acme.example.com)
curl -s https://tenant-pass.internal:8443/v1/credentials \
  -H "Authorization: Bearer $APP_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"pass\":\"$PASS\"}"
```

```json
{
  "tenant": "acme", "store": "postgres",
  "host": "pgbouncer.internal", "port": 6432, "database": "app",
  "username": "t_acme", "password": "umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM",
  "expires_at": "2026-11-03T12:13:59Z", "refresh_at": "2026-11-03T12:08:59Z"
}
```

## ドキュメント

| ドキュメント | 内容 |
| --- | --- |
| [設計](docs/ja/design.md) | コンポーネント、リクエストフロー、ローテーションモデル、設計上の判断 |
| [脅威モデル](docs/ja/threat-model.md) | tenant-pass が防ぐもの、防がないもの |
| [API](docs/ja/api.md) | HTTP API リファレンス |
| [パス形式](docs/ja/pass-format.md) | ゲートウェイ実装者向けのパス仕様とテストベクター |
| [パスワード導出](docs/ja/derivation.md) | ウィンドウとパスワード導出の仕様およびテストベクター |
| [設定](docs/ja/configuration.md) | すべての設定キー |
| [PostgreSQL](docs/ja/stores/postgres.md) · [MySQL](docs/ja/stores/mysql.md) · [Redis](docs/ja/stores/redis.md) | 最小権限によるストアのセットアップ |
| [tenant-pass-gateway](docs/ja/gateway.md) | forward-auth ゲートウェイコンポーネントと、Caddy/nginx/Traefik/Envoy の設定 |
| [ゲートウェイ連携](docs/ja/gateway-integration.md) | 独自のゲートウェイでパスに署名するためのルール |
| [バックグラウンドジョブ](docs/ja/jobs.md) | キューに入れられた処理やスケジュールされた処理のためのジョブチケット |
| [鍵管理](docs/ja/kms.md) | 鍵を Vault / OpenBao Transit に保管する |
| [クライアント連携](docs/ja/client-integration.md) | アプリケーションが認証情報を取得・キャッシュ・更新する方法 |
| [運用](docs/ja/operations.md) | デプロイ、鍵のローテーション、監視、インシデント対応 |

## ステータス

tenant-pass は **1.0 未満** です。パス形式と導出方式はバージョン管理されており（`tenant-pass/v1`）、テストベクターでカバーされていますが、設定や API の詳細はまだ変更される可能性があります。**外部のセキュリティ監査はまだ受けていません。** デプロイする前に [脅威モデル](docs/ja/threat-model.md) を必ずお読みください。

## セキュリティ

脆弱性は非公開で報告してください。[SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

Copyright 2026 KOBESOFT, Inc. Apache License 2.0 で提供します。[LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。
