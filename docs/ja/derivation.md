# パスワード導出（tenant-pass/v1）

[English](../en/derivation.md)

このドキュメントでは、tenant-pass がウィンドウとパスワードをどのように計算するかを規定し、方式のレビューや再実装ができるようにします。Go の実装は `internal/rotation` です。以下のテストベクターの生成に使った独立した Python 実装は `scripts/derivation_vectors.py` です。

## 表記

- `LP(x)`: `x` のバイト長を表す 4 バイトのビッグエンディアン整数に、`x`（UTF-8）を続けたもの。
- `BE64(n)`: `n` を符号付き 64 ビットのビッグエンディアン整数（2 の補数）で表したもの。
- `||`: 連結。
- `A = LP(store) || LP(node) || LP(account)`。ここで `store` は `postgres`、`mysql`、`redis` のいずれか、`node` は設定されたノード名、`account` はアカウント名です。
- `W`: 秒単位のウィンドウの長さ（`rotation.window`）。

## ウィンドウのオフセットと番号付け

```
offset = uint64_be(SHA-256("tenant-pass/v1/offset" || A)[0:8]) mod W
n(t)   = floor((unix(t) − offset) / W)
Start(n) = n·W + offset          (Unix seconds)
End(n)   = Start(n + 1)
```

オフセットによって、アカウントのローテーションはウィンドウ全体に均等に分散されます。オフセットはどの鍵にも依存しません。

## 鍵の選択

各ローテーション鍵には ID と `not_before` 時刻があります。ウィンドウ `n` では、`not_before ≤ Start(n)` を満たす鍵のうち、`not_before` が最も新しいものを使います。条件を満たす鍵がなければ、そのウィンドウのパスワードは存在しません。

## パスワードとソルト

選択された鍵のシークレットを `K`、その ID を `id` とすると、次のようになります。

```
password(n) = base64url_nopad( HMAC-SHA256(K, "tenant-pass/v1/password" || A || LP(id) || BE64(n)) )   → 43 chars
salt(n)     =                  HMAC-SHA256(K, "tenant-pass/v1/salt"     || A || LP(id) || BE64(n))     → 32 bytes
```

ソルトは、クライアント側でパスワードをハッシュするストアで使われます。

- **PostgreSQL** SCRAM-SHA-256 ベリファイア: ソルト = `salt(n)[0:16]`、反復回数 4096。
- **MySQL** `caching_sha2_password`: `salt(n)` の先頭 20 バイトを、それぞれ `alphabet[b & 0x3f]` によって crypt アルファベット `./0-9A-Za-z` に対応付けたもの。ラウンド数 5000。
- **Redis**: ソルトなし。ACL ハッシュは `hex(SHA-256(password))` です。

## 目標ウィンドウと更新

```
target(t) = n(t) + 1   if End(n(t)) − t ≤ renew_before
          = n(t)       otherwise
refresh_at(n) = End(n) − renew_before
```

## テストベクター

鍵のシークレット: バイト列 `00 01 02 … 1f`（32 バイト）。鍵 ID `k1`、`not_before` はすべてのウィンドウより前。`W = 900`。時刻 `t = 2026-11-03T12:00:00Z`（Unix 1793707200）。

| store / node / account | offset | n | Start | password(n) |
| --- | --- | --- | --- | --- |
| postgres / pg1 / t_acme | 539 | 1993007 | 1793706839 | `umDNGPl6N-JiorUfr9q4CsXCpmElUrtKZ2uOnp4T8RM` |
| mysql / my1 / t_acme | 601 | 1993007 | 1793706901 | `lRJgB4tM38aEGO4myi2zfoNWJK1vHuH-yu08BLhnjoU` |
| redis / rd1 / t_acme | 86 | 1993007 | 1793706386 | `tCGHXsj_Vw3vLJeWcto3NlgDT5WlxI3kq_yAAHsajeg` |

ソルト（16 進）:

- postgres: `ad3ceaff85f2029e16b5cf5890e411627895fe6d5367e8fc9818f4cd3b8ac398`
- mysql: `fa0dfbe05a2c07ae34e8eeec3d7a69aeaa9b60ab100db11c12d05615995b40f6`
- redis: `c493c646278a7ec0e7d27fe9acc557c08f7e8842fead295a7ef5a3107f9f0a84`

postgres の行に対応する PostgreSQL の SCRAM ベリファイア:

```
SCRAM-SHA-256$4096:rTzq/4XyAp4Wtc9YkOQRYg==$dwzLPDwP/7CwnPhHw/zWb7+XLxlpfEhoPyPLHE7dO9M=:7ljzKIBLT3xRViFwPrWVsXfr5RljubwmeqecuseE4yU=
```

redis の行に対応する Redis の ACL ハッシュ: `bd4475de5ef98729dc284dc27d1add155bb43ee7e74f34c45631e5fc3ffbb501`。

MySQL の SHA-crypt 実装は、OpenSSL（`openssl passwd -5`）および実際の MySQL 8.4 サーバーが生成したハッシュに対してテストされています（`internal/pwhash/pwhash_test.go`）。

## セキュリティに関する注記

- 長さプレフィックスによって HMAC の入力は単射になります。`("ab","c")` と `("a","bc")` が衝突することはありません。
- 異なるラベル（`password`、`salt`、`offset`）によって、鍵とハッシュの用途が分離されます。
- ストアの種類が入力に含まれるため、PostgreSQL ノードと Redis ノードにある同名のアカウントには、同じ鍵の下でも無関係なパスワードが割り当てられます。
- 鍵 ID が入力に含まれるため、鍵の名前を変えると、その鍵から導出されるすべてのパスワードが変わります。
- `K` を持つ者は誰でも、そこから導出される任意のパスワードを計算できます。ローテーション鍵はそれに見合った方法で保護し、漏洩が疑われる場合はローテーションしてください。
