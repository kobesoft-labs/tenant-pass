# 組み込みと拡張

[English](../en/embedding.md)

`tenant-pass` コマンドは、公開パッケージ `github.com/kobesoft-labs/tenant-pass/tenantpass` の薄いラッパーです。同じサーバーを動かし、**拡張**（同じリスナーで提供する追加の HTTP ルート）を足した独自のバイナリを作れます。

```go
err := tenantpass.Serve(ctx, tenantpass.Options{
	ConfigPath: "/etc/tenant-pass/config.json",
	Version:    version,
	Extensions: []tenantpass.Extension{{
		Name: "legacy",
		Mount: func(ctx context.Context, h tenantpass.Host) (map[string]http.Handler, error) {
			return map[string]http.Handler{"POST /v1/legacy": legacyHandler}, nil
		},
		Ready: legacyReady, // 任意。/readyz に含まれる
		Close: legacyClose, // 任意
	}},
})
```

## 拡張が得るもの

- 同じリスナーと TLS 設定（設定されていればクライアント証明書の検証も）。
- 同じレスポンスヘッダー（`Cache-Control: no-store`、CSP、`nosniff`、`Referrer-Policy`）。
- レディネス：`Ready` は `/readyz` に含まれます（コアのチェックとともに 5 秒キャッシュ）。
- グレースフルシャットダウン：拡張のルートへのリクエストも、コアと同じようにドレインされます。
- ロガー（`Host.Logger`。`extension` 属性つき）。

## 拡張が得ないもの

コアの設定は何も渡しません。ゲートウェイ鍵、ローテーション鍵、アプリトークンのハッシュ、ストアの認証情報、ディレクトリのいずれもです。パスを検証する必要がある拡張は、公開の `pass` パッケージを自分の鍵リストで使います。アプリケーションを認証する拡張は、それを自分で行います。こうすることで、コアの信頼境界は変わりません。拡張を足しても `/v1/credentials` や `/v1/job-tickets` が弱くなることはありません。

## 規則

- ルートのパターンは `net/http` の `ServeMux` の構文です。コアのパス（`/v1/credentials`、`/v1/job-tickets`、`/healthz`、`/readyz`）と `/` は使えません。2 つの拡張が同じパターンを登録することもできません。違反は起動時のエラーです。
- `Mount` は、設定を読み込んだあと、リスナーを開く前に 1 回だけ呼ばれます。`Mount` がエラーを返すと、サーバーは起動しません。
- 拡張はローテーション鍵と同じプロセスで動きます。拡張のコードは tenant-pass 本体と同じ注意で扱ってください。秘密をログに出さない、入力を厳格に解析する、リクエストの本文の大きさを制限する、などです。

典型的な使い方：同じ信頼境界の内側に置く必要がある、デプロイ固有のエンドポイント。または、クライアントが `/v1/credentials` に移行するまでの互換のために残す、旧いプロトコル。
