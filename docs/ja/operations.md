# 運用

[English](../en/operations.md)

## デプロイ

- **内部** ネットワーク上のロードバランサーの背後で、**2 つ以上のレプリカ** を実行してください。tenant-pass に到達できるのは、アプリケーション（と監視システム）だけにすべきです。
- コンテナイメージ（distroless、非 root、シェルなし）を使い、**読み取り専用のルートファイルシステム**、追加のケイパビリティなし、シークレットはファイルとしてマウント（Docker/Swarm のシークレット、Kubernetes のシークレット、systemd の認証情報）という構成にしてください。
- すべてのレプリカで、`rotation`、`nodes[].name`、ディレクトリの設定が同一でなければなりません。設定の変更はすべてのレプリカに展開してください。
- 時計は同期していなければなりません（NTP）。ずれは `renew_before` よりはるかに小さく（分単位ではなく秒単位）なければなりません。
- ヘルスチェック: ライブネスは `GET /healthz`、レディネスは `GET /readyz`。
- 停止猶予期間は `shutdown.drain + shutdown.timeout` より長くしてください（デフォルトでは 20 秒）。

例（Docker Compose）:

```yaml
services:
  tenant-pass:
    image: ghcr.io/kobesoft-labs/tenant-pass:<version>
    command: ["serve", "-config", "/etc/tenant-pass/config.json"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    stop_grace_period: 20s
    volumes:
      - ./config.json:/etc/tenant-pass/config.json:ro
    secrets: [tenant-pass.key, rotation-2026-11, pg1-admin-password]
```

## 初期構築

1. ストアの管理者アカウントとマーカーロールを用意します（[PostgreSQL](stores/postgres.md)、[MySQL](stores/mysql.md)、[Redis](stores/redis.md)）。
2. `tenant-pass gen-rotation-key -out rotation-YYYY-MM.key` — tenant-pass のレプリカにのみ配布します。（拡張子 `.key` は残してください。`*.key` は git と Docker のビルドコンテキストで無視されます。）
3. `tenant-pass gen-gateway-key …` — 秘密鍵はゲートウェイへ、公開鍵は tenant-pass へ。
4. 各アプリケーションについて `tenant-pass gen-app-token` — トークンはアプリケーションのシークレットストアへ、ハッシュは設定ファイルへ。
5. `tenant-pass check-config -config config.json -connect`。
6. tenant-pass を起動し、アプリケーションをテナントごとに切り替えていきます。初回の利用時に、tenant-pass は各アカウントの既存のパスワードを置き換えます。その後、保存されていた古いパスワードを利用者のシステムから削除してください。

## ローテーション鍵のローテーション

鍵には `not_before` があるため、すべてのレプリカが協調なしに同じウィンドウで切り替わります。

1. `tenant-pass gen-rotation-key -out rotation-2026-12.key`。
2. 展開が完了する時刻より十分後の `not_before`（たとえば翌日の 03:00 UTC）を指定して、すべてのレプリカに追加します。
   ```json
   "keys": [
     {"id": "r-2026-11", "secret_file": "/run/secrets/rotation-2026-11", "not_before": "2026-11-01T00:00:00Z"},
     {"id": "r-2026-12", "secret_file": "/run/secrets/rotation-2026-12", "not_before": "2026-12-01T03:00:00Z"}
   ]
   ```
3. `not_before` 以降、その時刻以降に **開始する** すべてのウィンドウで新しい鍵が使われます。それ以外には何も起きません。
4. `not_before + window + renew_before` を過ぎたら、古い鍵を削除して再度展開します。

鍵の `id` やシークレットをその場で変更することは決してしないでください。どのウィンドウでどの鍵を使うかについて、すべてのレプリカの認識が一致していなければならないからです。`not_before` が未来にある鍵の追加は、それ以前にその鍵を使うレプリカがないため、ローリングアップデート中でも安全です。展開が `not_before` より前に完了するようにしてください。

**緊急時（鍵が露出した場合）:** `not_before` = 現在時刻 + 展開にかかる時間 として新しい鍵を追加し、展開します。古い鍵を削除するのは、新しい鍵の `not_before` が **少なくとも 1 ウィンドウ過去になってから** にしてください（起動時には、設定された最も古い鍵が 1 ウィンドウ全体にわたって有効であることが求められます）。古い鍵から導出されたパスワードは、そのウィンドウが終了した時点（PostgreSQL）、または次の発行やスイープで置き換えられた時点（MySQL、Redis）で使えなくなります。PostgreSQL で即座に遮断するには、影響を受けるロールに `ALTER ROLE … VALID UNTIL 'now'` を実行してください（クライアントは認証情報を再取得します）。あわせて、既存のセッションも終了させてください（下記を参照）。失効によって開いている接続が閉じられることはありません。

## ウィンドウの変更

`rotation.window` を変更すると、すべてのアカウントのウィンドウ番号とオフセットが変わります。ローリングアップデート中は新旧のレプリカの認識が食い違い、互いの設定を上書きし合います（「管理対象外」の境界）。短時間の全停止を伴う手順で変更してください。すべてのレプリカを停止し、デプロイし、起動します。クライアントは 1 回だけ認証情報を再取得します。

## 監視

すべてのイベントは標準出力に JSON 行として出力されます。有用なアラートは次のとおりです。

| 条件 | 意味 |
| --- | --- |
| `msg=credential` かつ `reason=account_refused` | ディレクトリが、ストアの拒否するアカウント（特権を持つ、管理対象外、存在しない）を指しています。直ちに調査してください。設定ミスか、ディレクトリへの攻撃です。 |
| `reason=pass_signature` または `pass_unknown_key` | 偽造されたパス、または tenant-pass が知らない鍵を持つゲートウェイ。 |
| `reason=pass_audience` | あるアプリケーションが、別のアプリケーション向けのパスを提示しました。 |
| `reason=distinct_tenants`（429） | あるアプリケーションが異常に多くのテナントにアクセスしています。侵害の可能性があります。 |
| `reason=clock_skew` | あるレプリカの時計とストアサーバーの時計の差が `max_clock_skew` を超えています。そのレプリカは書き込みを拒否します。（レプリカまたはデータベースの）NTP を修正してください。 |
| `reason=directory_error` / `store_error` / `timeout` | バックエンドの問題。 |
| `ERROR` レベルの `msg=sweep` | MySQL/Redis のスイープが失敗しています。期限切れのパスワードが削除されていません。 |
| `reason=distinct_tenants_jobs` | あるジョブのワークロードが、その枠を超える数のテナントにアクセスしています。 |
| `app` ごとの `msg=job_ticket` の量 | 発行されたチケット。異常な量に対してアラートを出してください。 |
| `kms` を含む `error` | Vault/OpenBao に到達できないか、拒否されています。キャッシュされていないパスワードを導出できません。 |
| `app` ごとの `result=ok` の発生率 | アプリケーションごとのベースライン。逸脱したらアラートを出してください。 |
| `/readyz` の失敗 | バックエンドに到達できないか、レプリカがドレイン中です。 |

## インシデント対応

| 侵害が疑われる対象 | 対応 |
| --- | --- |
| アプリケーション | その `apps` エントリーを削除（またはトークンハッシュを置き換え）して展開します。これで、そのアプリケーションは認証情報を取得できなくなります。すでに保持している認証情報は、最大で 1 ウィンドウと `renew_before` の間、新規接続に使えます（MySQL/Redis ではさらにスイープ 1 回分）。**開いている接続は失効によって閉じられません**。影響を受けるアカウントの接続を終了させてください（PostgreSQL では `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 't_acme'`、MySQL では `SHOW PROCESSLIST` から `KILL <id>`、Redis ではすべてのサーバーで `CLIENT KILL USER t_acme`）。その `app` の `msg=credential` を確認し、どのテナントにアクセスしたかを調べてください。 |
| ゲートウェイ鍵 | `gateway_keys` からその鍵を削除して展開し、ゲートウェイに新しい鍵をデプロイします。 |
| ジョブ発行者（スケジューラー）の鍵 | `job_tickets.trusted_issuers` から削除して展開します。その鍵で署名されたチケットは即座に使えなくなります。 |
| tenant-pass 自身のジョブ用の鍵 | `job_tickets.signing_key` を（新しい `id` で）置き換えて展開します。発行済みで有効期限内のチケットは使えなくなるため、ジョブは新しいチケットを入手しなければなりません。 |
| Vault トークン | Vault でトークンを失効させます。そのホストは鍵を使えなくなります。 |
| ローテーション鍵 | 上記の「緊急時」を参照してください。あわせて、想定外のアドレスからのログインがないかストアのログを確認してください。 |
| tenant-pass ホスト | すべてのテナントが露出したものとして扱ってください。ローテーション鍵、ストアの管理者パスワード、TLS 鍵をローテーションし、ストアのログを確認してください。 |
| ストアの管理者パスワード | ストアとシークレットファイルの両方でパスワードを変更し、レプリカを再起動してください。 |

## リリースの検証

リリースイメージは `.github/workflows/release.yml` によってビルドされ、SBOM と SLSA の来歴（provenance）付きでプッシュされ、Sigstore（キーレス）で署名されます。デプロイ前に検証してください。

```sh
cosign verify ghcr.io/kobesoft-labs/tenant-pass:<version> \
  --certificate-identity-regexp '^https://github.com/kobesoft-labs/tenant-pass/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

タグではなくダイジェスト（`ghcr.io/…@sha256:…`）でデプロイしてください。

## アップグレード

リリースノートで別途記載がない限り、隣接するバージョンのレプリカは並行して稼働できます。導出方式とパス形式はバージョン管理されています（`tenant-pass/v1`）。変更する場合は、新しいラベルと移行手順が併せて提供されます。
