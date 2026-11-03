# バックグラウンドジョブ（ジョブチケット）

[English](../en/jobs.md)

パス（pass）は 1 つのリクエストに結び付いているため、寿命は数秒です。どのリクエストの外側でも **後から** 実行される処理には、1 つのテナントに対する独自の認可が必要です。それが **ジョブチケット** です。

| | パス | ジョブチケット |
| --- | --- | --- |
| 署名者 | ゲートウェイ | tenant-pass 自身、または利用者が運用する信頼された発行者（スケジューラー） |
| 記載するもの | ホストまたはテナント | 常にテナント ID |
| 寿命 | 数秒（`pass.max_ttl`、5 分以下） | 数分から数時間（`job_tickets.max_ttl`、24 時間以下） |
| 暗黙のアサーション | `tenant-pass/v1/pass` | `tenant-pass/v1/job` |
| 引き換え先 | `POST /v1/credentials` `{"pass": …}` | `POST /v1/credentials` `{"ticket": …}` |
| レート制限 | `limits.max_tenants_per_minute` | `apps[].jobs.max_tenants_per_minute`（別枠） |

暗黙のアサーションが異なるため、同じ鍵で両方に署名した場合でも、パスをチケットとして使うことも、チケットをパスとして使うことも決してできません。

## チケットを入手する 2 つの方法

### 1. リクエストの継続: `POST /v1/job-tickets`

ユーザーのリクエストを（新しいパスを持って）処理している間に、アプリケーションはパスをチケットと交換し、そのチケットをジョブのペイロードに入れます。ジョブは後で、チケットが失効するまで、必要なだけ何度でもチケットを認証情報と引き換えます。

```
user request ──▶ gateway ──pass──▶ app ──POST /v1/job-tickets {"pass"}──▶ tenant-pass
                                    │ ◀──────────── {"ticket", "tenant", "expires_at"}
                                    └─ enqueue job {tenant: acme, ticket: …}
later:  worker ──POST /v1/credentials {"ticket"}──▶ tenant-pass ──▶ credential for acme
```

これは、ユーザーが開始した処理（エクスポート、インポート、ユーザーが要求したレポートの送信など）に使ってください。

要件:

- `job_tickets.signing_key` が設定されていること（ローカルの鍵、または Vault Transit）。
- アプリケーションに `"jobs": {"issue": true}` があること。
- パスがそのアプリケーションに対して有効であり、テナントが有効化されていて、そのアプリケーションに対して許可されていること。tenant-pass は **チケットを発行する時点で** テナントを解決するため、チケットには正規のテナント ID が記載されます。
- 発行は、認証情報と同じ異なるテナント数の枠に算入されるため、その制限を回避する目的には使えません。

### 2. スケジュールされた処理: 信頼された発行者

どのリクエストからも開始されない処理もあります。夜間レポート、クリーンアップ、マイグレーション、課金処理などです。これらのためにパスを生成できる者はいません。その代わりに、**利用者が運用し、信頼する** コンポーネント（スケジューラー、管理画面のジョブランナーなど）が自身の鍵でチケットに署名し、tenant-pass はその鍵を `job_tickets.trusted_issuers` として信頼します。

```
scheduler (holds issuer key) ──signs ticket {aud: reports, tenant: acme, exp: +1h}──▶ worker
worker ──POST /v1/credentials {"ticket"}──▶ tenant-pass ──▶ credential for acme
```

どのテナントについて処理を実行するかは、発行者が決めます。それでも tenant-pass は、引き換えのたびに、テナントが存在し、有効化されていて、そのアプリケーションに対して許可されていることをチェックし、アプリケーションのジョブ用レート制限を適用します。

発行者が署名する方法:

- Go: `pass.Signer{KeyID: "scheduler-1", Key: key}.SignJob(ctx, pass.JobClaims{...})`。Vault Transit の鍵を使う場合は `Remote:` を指定します。
- コマンドライン: `tenant-pass sign-job-ticket -key scheduler.key -kid scheduler-1 -aud reports -tenant acme -ttl 1h`。
- その他の言語: 以下の形式に従えば、任意の PASETO v4.public ライブラリを使えます。

**発行者はアプリケーションから分離してください。** アプリケーションがチケットに署名できると、侵害されたアプリケーションがすべてのテナントの認証情報を入手できてしまいます。これはまさに tenant-pass が防ぐために存在するものです。発行者の鍵は、別にデプロイされ、別に保護されたコンポーネントに置いてください。

## 設定

```json
"job_tickets": {
  "signing_key": {"id": "tp-jobs-2026-11", "transit": {"key": "tenant-pass-jobs", "version": 1}},
  "trusted_issuers": [{"id": "scheduler-1", "public_key_file": "/etc/tenant-pass/scheduler-1.pub"}],
  "max_ttl": "1h"
},
"apps": [
  {"name": "billing", "token_sha256": "…", "jobs": {"issue": true, "max_ttl": "30m", "max_tenants_per_minute": 60}},
  {"name": "reports", "token_sha256": "…", "jobs": {"trusted_issuers": ["scheduler-1"], "max_tenants_per_minute": 600}}
]
```

- `jobs` を持たないアプリケーションは、チケットを入手することも引き換えることもできません（`403 denied`）。
- `jobs.issue` は `POST /v1/job-tickets` を許可します。
- `jobs.trusted_issuers` には、そのアプリケーションがどの外部発行者のチケットを引き換えてよいかを列挙します。tenant-pass 自身の鍵で署名されたチケットは常に受け付けられます（tenant-pass は、チケットに記載されたアプリケーションに対してのみそれを発行します）。列挙されていない発行者のチケットは拒否されます（`403`、監査ログでは `issuer_not_allowed`）。
- チケットの寿命（`exp − iat`）は、アプリケーションの `jobs.max_ttl` を超えてはなりません。これは発行時 **と** 引き換え時の両方で、外部発行者のチケットについても適用されます。また、`job_tickets.max_ttl` も超えてはなりません。どちらも、ジョブが許す限り短くしてください。

[configuration.md](configuration.md#job_tickets) を参照してください。

## チケット形式

構成はパスと同じです（[pass-format.md](pass-format.md)）。違いは次のとおりです。

- 暗黙のアサーション: `tenant-pass/v1/job`。
- フッター `{"kid": "<issuer key ID>"}`: tenant-pass 自身の `signing_key.id`、または `trusted_issuers[].id`。
- クレームはちょうど `aud`（アプリケーション）、`tenant`（テナント ID）、`iat`、`exp`、`jti` です。`host` はありません。
- `exp − iat ≤ job_tickets.max_ttl`（デフォルト 1 時間、絶対的な上限 24 時間）。

## セキュリティ上の性質と制限

- チケットは、失効するまでの間、1 つのテナントと 1 つのアプリケーションに対するベアラー型の権限（ケイパビリティ）です。シークレットとして保管してください。ジョブのペイロードの中にのみ置き、決してログに記録しないでください。tenant-pass はチケットを決してログに記録しません。
- 失効リストはありません。失効させるには、発行者の鍵を削除して（または tenant-pass 自身の `signing_key` をローテーションして）展開するか、ディレクトリでテナントを無効化してください。
- `jobs.issue` を持つアプリケーションが侵害されると、正規に受け取ったパスをチケットに変換し、それらのテナントへのアクセスを数秒から `jobs.max_ttl` まで延長できます。`issue` は必要なアプリケーションに対してのみ有効にし、`max_ttl` は短くしてください。
- チケットで取得した認証情報は通常のウィンドウのルールに従い、チケットより最大で 1 ウィンドウ分長く生き残ることがあります。
- ジョブ用のレート制限は **別枠** です。アプリケーションは、パスで最大 `limits.max_tenants_per_minute` 個のテナントに、**加えて** チケットで `jobs.max_tenants_per_minute` 個のテナントに到達できます（レプリカごと）。ジョブ用の枠は、ジョブが実際に必要とする値に設定してください。
- 1 つのパスと交換できるチケットは **1 枚** です（tenant-pass はパスの ID を失効まで記憶します。レプリカごとなので、N 台なら最大 N 枚）。2 回目の交換は `403`（監査 `pass_already_used`）になります。別の理由（ディレクトリのエラー、無効化されたテナント）で発行に失敗した場合は、パスは解放され、再試行できます。この記憶領域はアプリケーションごとに上限があり（1 つのアプリケーションが他のアプリケーションの分まで埋め尽くすことはできません）、満杯になるとフェイルクローズします。同じパスで認証情報を取ることは引き続きできます。チケットはキューに置かれる可能性のあるベアラートークンです。キューを保護してください。
- 発行者の範囲は狭くしてください。あるアプリケーションに対して列挙された発行者は、そのアプリケーションがアクセスできる **任意の** テナントのチケットに署名できます。
