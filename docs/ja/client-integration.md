# クライアント連携

[English](../en/client-integration.md)

アプリケーションがテナントの認証情報をどのように取得、保持、更新すべきかを説明します。

## リクエストごとの流れ

1. ゲートウェイが使うヘッダー（たとえば `Tenant-Pass`）からパスを読み取ります。パスがなければ、そのリクエストにはテナントデータへのアクセス権がありません。リクエストを失敗させてください。
2. そのテナントのキャッシュ済み認証情報を **プロセスのメモリ内で** 探します。存在し、かつ `now < refresh_at` であれば、それを使います。
3. そうでなければ、パスを付けて `POST /v1/credentials` を呼び出し、結果を `refresh_at` までキャッシュして使います。
4. `host:port`（と `database`）に `username` / `password` で接続します。

```text
credential = cache.get(tenant)
if credential is None or now >= credential.refresh_at:
    credential = tenant_pass.fetch(pass)          # POST /v1/credentials
    cache.put(tenant, credential)
conn = connect(credential)
if conn failed with authentication error:
    credential = tenant_pass.fetch(pass, repair=True)
    cache.put(tenant, credential)
    conn = connect(credential)                    # once; do not loop
```

キャッシュのキーは、パスから解決したテナント（またはレスポンスの `tenant` フィールド）です。キャッシュをプロセス間やホスト間で共有してはいけません。

## ルール

- **メモリ内のみ。** 認証情報をディスク、共有キャッシュ（Redis、memcached）、データベース、ログ、エラーレポート、メトリクスのラベルに決して書き込まないでください。アプリトークンはコードではなく、プロセスの環境変数またはシークレットマウントに置いてください。
- **`refresh_at` で更新する。** その時点から tenant-pass は次のウィンドウを払い出します。それより早く更新しても害はありません（同じパスワードが返ります）。PostgreSQL では、`refresh_at` を認証情報の実質的な終了時刻として扱ってください。いずれかのクライアントが更新した時点で、以前のパスワードでは新規接続を開けなくなります。MySQL と Redis では、以前のパスワードは `expires_at`（さらに最大でスイープ 1 回分）まで使い続けられます。
- **認証失敗時は `"repair": true` を付けて 1 回だけリトライする。**
  - PostgreSQL: SQLSTATE `28P01`（`invalid_password`）。
  - MySQL: エラー `1045`（`ER_ACCESS_DENIED_ERROR`）。
  - Redis: `WRONGPASS`。
  
  PostgreSQL ではローテーション直後にこれが起きるのは想定内です（ロールごとにパスワードは 1 つ）。MySQL/Redis ではまれなはずです。ループでリトライしないでください。
- **開いている接続は問題ない。** パスワードの変更や失効によって既存の接続が閉じられることはありません。接続プールはそれらを保持し続けられます。現在のパスワードが必要なのは新規接続だけです。
- **更新にはパスまたはチケットが必要。** 認証情報は、新しいパスを持つリクエストを処理している間に更新できます。後から実行される処理は、代わりにジョブチケットを使います。リクエストを処理している間に `POST /v1/job-tickets` で（有効になっている場合）、またはスケジューラーからチケットを入手し、`{"pass": …}` の代わりに `{"ticket": …}` を送ってください。[jobs.md](jobs.md) を参照してください。
- **エラー**: `400`/`401`/`403` はそのパスについては恒久的なエラーです（ログに記録してリクエストを失敗させてください）。`429`/`503` はバックオフしてリトライできます。
- **TLS**: tenant-pass の証明書を検証してください。検証を無効にしないでください。

## 接続プール

- プールはテナントごとに分けてください。テナント A のプールをテナント B に使ってはなりません。
- キャッシュ済みの認証情報が更新されたら、プール内の新規接続は新しいパスワードを使うべきです。作成時に静的なパスワードを受け取るプールは作り直す必要があります（またはパスワードのコールバックを使ってください。たとえば `pgx` の `BeforeConnect` や `lib/pq` のコネクター）。
- アクティブでなくなったテナントのアイドルなプールは閉じ、その認証情報がメモリから消えるようにしてください。

## PgBouncer とプロキシ

`connect` はプーラーを指すようにしてください。[PostgreSQL › PgBouncer](stores/postgres.md#pgbouncer) を参照してください。

## 例（Go）

```go
type cred struct {
	Username, Password, Host, Database string
	Port                               int
	RefreshAt                          time.Time `json:"refresh_at"`
}

func fetch(ctx context.Context, hc *http.Client, token, pass string, repair bool) (*cred, error) {
	body, _ := json.Marshal(map[string]any{"pass": pass, "repair": repair})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://tenant-pass.internal:8443/v1/credentials", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tenant-pass: %s", resp.Status)
	}
	var c cred
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
```
