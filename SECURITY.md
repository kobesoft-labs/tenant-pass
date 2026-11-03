# Security policy

[日本語は下にあります](#セキュリティポリシー)

tenant-pass is security infrastructure. We take reports seriously and appreciate coordinated disclosure.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's private vulnerability reporting:

https://github.com/kobesoft-labs/tenant-pass/security/advisories/new

Please include:

- the affected version or commit;
- a description of the issue and its impact;
- steps to reproduce, or a proof of concept;
- any suggested fix.

We aim to acknowledge reports within **3 business days** and to provide an assessment within **10 business days**. We will keep you informed, credit you in the advisory unless you prefer otherwise, and agree on a disclosure date with you (normally no later than 90 days after the report).

## Scope

In scope: this repository — the server, the `pass` package, the documented pass format and password derivation, and the documented store setup.

Particularly interesting:

- obtaining a credential without a valid pass for that tenant, or across applications;
- making tenant-pass modify an account that is privileged or not marked as managed;
- any path to plaintext or unverified TLS without the explicit opt-in;
- leaking passwords, keys or tokens (logs, errors, responses, timing);
- weaknesses in the pass format, PASETO handling, or password derivation;
- forward-only rotation violations (resurrecting old passwords, extending expiry).

Out of scope: vulnerabilities that require a compromised gateway, directory, store server or tenant-pass host (see the [threat model](docs/en/threat-model.md)); misconfigurations explicitly documented as insecure (`allow_insecure_plaintext`); denial of service by an authenticated application within its configured limits.

## Supported versions

Before 1.0, only the latest release receives security fixes.

## Hardening checklist

See [docs/en/operations.md](docs/en/operations.md) and the store guides. In short: internal network only, TLS everywhere, least-privilege admin accounts, secrets as files, two or more replicas, NTP, and alerts on `account_refused`, `pass_signature` and `rate_limited`.

---

# セキュリティポリシー

tenant-pass はセキュリティの基盤となるソフトウェアです。脆弱性の報告は、非公開で受け付けます。

## 脆弱性の報告

**公開の Issue は作らないでください。** GitHub の非公開の脆弱性報告から送ってください。

https://github.com/kobesoft-labs/tenant-pass/security/advisories/new

次の内容を含めてください。

- 対象のバージョンまたはコミット
- 問題の内容と影響
- 再現手順、または概念実証（PoC）
- 修正案（あれば）

**3 営業日以内**に受領を連絡し、**10 営業日以内**に評価結果をお知らせします。公開日は報告者と相談して決めます（通常は報告から 90 日以内）。希望されない場合を除き、アドバイザリに報告者のお名前を記載します。

## 対象

このリポジトリ（サーバー、`pass` パッケージ、文書化したパスの形式とパスワードの導出、文書化したストアの設定手順）が対象です。

特に次のような問題を歓迎します。

- そのテナントの有効なパスなしで資格情報を得られる、またはアプリケーションをまたいで得られる
- 特権を持つアカウントや、管理対象の印がないアカウントを tenant-pass に変更させられる
- 明示的な許可なしに、平文の通信や検証されない TLS になる経路がある
- パスワード・鍵・トークンが漏れる（ログ、エラー、応答、処理時間の差）
- パスの形式、PASETO の扱い、パスワードの導出の弱点
- ローテーションが前にしか進まないという約束が破られる（古いパスワードの復活、期限の延長）

対象外: ゲートウェイ・ディレクトリ・ストアのサーバー・tenant-pass のホストが乗っ取られていることが前提の問題（[脅威モデル](docs/ja/threat-model.md)を参照）、安全でないと明記した設定（`allow_insecure_plaintext`）、認証済みのアプリケーションが設定された上限の範囲内で起こすサービス妨害。

## サポートするバージョン

1.0 より前は、最新のリリースだけにセキュリティ修正を提供します。
