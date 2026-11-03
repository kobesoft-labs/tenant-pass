# パス形式（tenant-pass/v1）

[English](../en/pass-format.md)

これはパスの規範となる仕様です。ゲートウェイの実装者に必要なのは、このドキュメントと PASETO v4 ライブラリだけです。Go の実装は [`pass`](../../pass) パッケージにあり、直接インポートして使えます。

## トークン

パスは [PASETO](https://github.com/paseto-standard/paseto-spec) **v4.public** トークン（Ed25519）です。

```
v4.public.<base64url(message || signature)>.<base64url(footer)>
```

| 部分 | 値 |
| --- | --- |
| バージョン / 用途 | `v4.public` のみ。それ以外のヘッダーは拒否されます。 |
| 暗黙のアサーション | ASCII バイト列 `tenant-pass/v1/pass` そのもの。必須。署名には含まれますが、送信はされません。 |
| フッター | 必須。JSON オブジェクト `{"kid":"<key ID>"}` で、それ以外は含めません。最大 256 バイト。 |
| メッセージ | 以下のクレームを持つ JSON オブジェクト。 |
| 全体の長さ | 最大 2048 バイト。 |

Base64url はパディングなしで、非正規のエンコーディング（未使用ビットが 0 でないもの）は拒否されます。

暗黙のアサーションはドメイン分離の役割を果たします。同じ鍵で別の目的のために（あるいは将来の tenant-pass のバージョンのために）署名されたトークンは、検証に失敗します。**省略しないでください。** ほとんどの PASETO ライブラリは、これを `sign` / `verify` のパラメーターとして受け取ります（「implicit assertion」や `i` と呼ばれることもあります）。

## フッター

```json
{"kid":"gw1"}
```

`kid` は `^[a-z][a-z0-9_-]{0,62}$` に一致し、かつ tenant-pass に設定された `gateway_keys[].id` の値のいずれかでなければなりません。tenant-pass が検証前にフッターを読むのは鍵を選ぶためだけです。フッターは署名の対象に含まれます。

## クレーム

メッセージは、**ちょうど** 以下のメンバーを持つ JSON オブジェクトです。未知のメンバーと重複したメンバーは拒否されます。

| クレーム | 必須 | 形式 | 意味 |
| --- | --- | --- | --- |
| `aud` | はい | `^[a-z][a-z0-9_-]{0,62}$` | ゲートウェイがリクエストを転送する先のアプリケーション名（tenant-pass の `apps[].name`）。 |
| `host` | `host` / `tenant` のいずれか一方 | 正規化済みホスト名（後述） | リクエストのホスト名。tenant-pass はディレクトリの `by_host` ルックアップでこれを解決します。 |
| `tenant` | `host` / `tenant` のいずれか一方 | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$` | ゲートウェイがすでに把握している場合のテナント ID。`by_tenant` で解決されます。 |
| `iat` | はい | `YYYY-MM-DDTHH:MM:SSZ` | 発行時刻。UTC、秒単位（小数なし）、`Z` サフィックス。 |
| `exp` | はい | `YYYY-MM-DDTHH:MM:SSZ` | 有効期限。同じ形式。 |
| `jti` | はい | `^[A-Za-z0-9_-]{16,128}$` | ランダムな識別子。128 ビット以上を推奨します。ゲートウェイのログと突き合わせられるように、tenant-pass がログに記録します。 |

### 正規化済みホスト名

tenant-pass は正規化を行いません。ゲートウェイは厳密に次の形式で送らなければなりません。

- 小文字の ASCII 英字、数字、`-` から成るラベルを `.` で区切ったもの
- 国際化ドメイン名は A ラベル（`xn--…`）に変換したもの
- ポートなし、末尾のドットなし、空のラベルなし
- 各ラベルは 1〜63 文字で、`-` で始まったり終わったりしない
- 全体で最大 253 文字、ラベルは 2 つ以上
- IP アドレスではない

### 時刻のルール

`now` を tenant-pass の時計、`leeway` を `pass.leeway`（デフォルト 5 秒）とすると、次が成り立たなければなりません。

- `exp > iat`
- `exp − iat ≤ pass.max_ttl`（デフォルト 60 秒、上限 300 秒）
- `now < exp`（有効期限には猶予なし）
- `iat ≤ now + leeway`

推奨: `exp = iat + 30s`。

## 検証の順序（tenant-pass）

1. 長さが 2048 以下であること、ヘッダーが `v4.public.` であること、フッターがあること。
2. フッターを厳格にパースし、`kid` を検索する。未知であれば拒否する。
3. その鍵と暗黙のアサーションで署名を検証する。
4. クレームを厳格にパースして検証する（形式、`host`/`tenant` のちょうど一方があること）。
5. 有効期間と時刻のルール。
6. `aud` を認証済みのアプリケーションと比較する。

## テストベクター

| 入力 | 値 |
| --- | --- |
| Ed25519 シード | `0x01` が 32 バイト |
| 公開鍵（16 進） | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| フッター | `{"kid":"gw1"}` |
| 暗黙のアサーション | `tenant-pass/v1/pass` |
| メッセージ | `{"aud":"billing","host":"acme.example.com","iat":"2026-11-03T12:00:00Z","exp":"2026-11-03T12:00:30Z","jti":"AAAAAAAAAAAAAAAAAAAAAA"}` |

期待されるトークン（Ed25519 は決定的なので、仕様に準拠した署名者はまさにこれを生成します）:

```
v4.public.eyJhdWQiOiJiaWxsaW5nIiwiaG9zdCI6ImFjbWUuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDI2LTExLTAzVDEyOjAwOjAwWiIsImV4cCI6IjIwMjYtMTEtMDNUMTI6MDA6MzBaIiwianRpIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQSJ9lGRulfEQdJnx_Iagf4Fp94_8eSIifNPHT82HGA8KqWhSX_KikCQafPjF2Ntupw3XnYtRoZ6xe1-uf46uZcHoDQ.eyJraWQiOiJndzEifQ
```

実装はこのトークンをバイト単位で完全に同じように生成する必要があり、tenant-pass の検証器は（時計が `iat` と `exp` の間にあれば）これを受け付けます。テストは `pass/pass_test.go` の `TestPublishedVector` です。基盤となる PASETO 実装は、公式の PASETO v4 テストベクターで検証されています。

## 例

### Go

```go
import "github.com/kobesoft-labs/tenant-pass/pass"

s := pass.Signer{KeyID: "gw1", Key: privateKey} // ed25519.PrivateKey
now := time.Now()
p, err := s.Sign(pass.Claims{
    Audience: "billing",
    Host:     "acme.example.com",
    IssuedAt: now,
    Expiry:   now.Add(30 * time.Second),
})
```

### PHP（paragonie/paseto、低レベル API）

paragonie/paseto の高レベルな `Builder` は暗黙のアサーションを JSON エンコードしてしまうため、暗黙のアサーションを生の文字列として受け取るプロトコルクラスを直接使ってください。

```php
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Protocol\Version4;

$now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
$claims = json_encode([
    'aud'  => 'billing',
    'host' => 'acme.example.com',
    'iat'  => $now->format('Y-m-d\TH:i:s\Z'),
    'exp'  => $now->modify('+30 seconds')->format('Y-m-d\TH:i:s\Z'),
    'jti'  => rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '='),
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

$token = Version4::sign(
    $claims,
    new AsymmetricSecretKey($secretKeyBytes, new Version4()),
    '{"kid":"gw1"}',          // footer
    'tenant-pass/v1/pass'     // implicit assertion (exact bytes)
);
```

注意: ライブラリによっては、デフォルトで独自のクレーム（たとえば異なる形式のデフォルトの `exp` や `nbf`）を追加したり、暗黙のアサーションを JSON としてエンコードしたりするものがあります。また、ライブラリの API はメジャーバージョン間で変わります。tenant-pass は未知のクレームを拒否し、暗黙のアサーションが厳密にバイト列 `tenant-pass/v1/pass` であることを要求します。デプロイする前に、ライブラリの出力を上記のテストベクターと照合してください。ライブラリでこれを生成できない場合は、低レベルの PASETO 署名プリミティブを直接使ってください。
