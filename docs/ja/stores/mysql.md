# MySQL

[English](../../en/stores/mysql.md)

## 仕組み

各テナントは、`caching_sha2_password` を使う MySQL アカウント `'t_acme'@'%'` です。MySQL にはパスワードごとの有効期限はありませんが、8.0.14 以降、1 つのアカウントが 2 つのパスワードを保持できます（「デュアルパスワード」）。tenant-pass はこれを 2 つのスロットとして使います。

| フェーズ | プライマリ | セカンダリ |
| --- | --- | --- |
| 通常 | ウィンドウ `n` | — |
| 更新（`refresh_at` から） | ウィンドウ `n+1` | ウィンドウ `n` |
| `End(n)` 以降（スイーパー） | ウィンドウ `n+1` | — |

`GET_LOCK` の下で実行されるステートメントは次のとおりです。

```sql
ALTER USER 't_acme'@'%' IDENTIFIED WITH caching_sha2_password AS 0x2441243030352…;              -- set primary
ALTER USER 't_acme'@'%' IDENTIFIED WITH caching_sha2_password AS 0x…  RETAIN CURRENT PASSWORD;  -- rotate
ALTER USER 't_acme'@'%' DISCARD OLD PASSWORD;                                                   -- drop secondary
```

- tenant-pass は `caching_sha2_password` のハッシュ（20 バイトのソルト、5000 ラウンドの SHA-crypt）を自分で計算し、16 進リテラルとして送信します。平文がサーバー、バイナリログ、一般ログ、performance_schema に届くことはありません。
- 更新中は両方の認証情報が使えるため、クライアントにはローテーションによる認証失敗は見えません。
- **スイーパー**（`rotation.sweep_interval` ごと）が、ウィンドウの終了したパスワードを削除します。1 ウィンドウの間まったく要求されなかったアカウントには、最終的に誰も知らないランダムなパスワードが残ります。
- tenant-pass が導出していないパスワード（たとえばプロビジョニングで設定した初期パスワード）は、初回の利用時に削除されます。

## 対応バージョン

MySQL 8.0.27 以降、8.4 LTS、9.x。（8.4 でテスト済み。）MariaDB はサポートしていません（認証プラグインが異なり、デュアルパスワードもないため）。

## セットアップ

管理者ユーザーで実行します。

```sql
-- Marker role: tenant-pass only touches accounts granted this role.
CREATE ROLE tenant_pass_managed;

-- The account tenant-pass logs in as.
CREATE USER tenant_pass_admin IDENTIFIED BY '<random>' REQUIRE SSL;
GRANT CREATE USER ON *.* TO tenant_pass_admin;            -- needed for ALTER USER on other accounts
GRANT SELECT ON mysql.user TO tenant_pass_admin;          -- read authentication_string / privileges
GRANT SELECT ON mysql.global_grants TO tenant_pass_admin; -- check dynamic privileges
GRANT SELECT ON mysql.role_edges TO tenant_pass_admin;    -- check roles
GRANT SELECT ON mysql.db TO tenant_pass_admin;            -- check grants on system schemas
GRANT SELECT ON mysql.tables_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.columns_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.procs_priv TO tenant_pass_admin;
GRANT SELECT ON mysql.proxies_priv TO tenant_pass_admin;  -- check proxy rights
```

管理対象ロール自体は権限を一切持ってはなりません（マーカーにすぎません）。テナントには、直接、または自身のデータベースに対して権限を付与してください。

テナントごとに次を実行します。

```sql
CREATE USER t_acme IDENTIFIED BY '<any initial password>';
GRANT tenant_pass_managed TO t_acme;
GRANT SELECT, INSERT, UPDATE, DELETE ON acme.* TO t_acme;   -- what the tenant needs
```

**`CREATE USER` について。** MySQL には、他のアカウントのパスワード変更を許可する、これより狭い権限がありません。`CREATE USER` があると、`tenant_pass_admin` は `SYSTEM_USER` を持たない任意のアカウントを変更できます。したがって、次のようにしてください。

- テナント以外の管理者アカウントとアプリケーションアカウントがすべて `SYSTEM_USER` を持つ（MySQL 8.0.16 以降では `root` にデフォルトで付与されます）か、別の方法で手の届かないところにあることを確認してください。
- `tenant_pass_admin` には `SYSTEM_USER` を **与えないでください**。
- tenant-pass 自身の安全性チェック（後述）は第二の防衛線であり、唯一の防御ではありません。

`mysql.user` には全アカウントのパスワードハッシュが含まれています。これらはログインには使えませんが、人が設定した弱いパスワードのオフライン推測を可能にします。`tenant_pass_admin` の認証情報はそれに見合った扱いをしてください。

## 安全性チェック

ロックの下で、tenant-pass は次の条件をすべて満たさない限り拒否します（監査ログに `account_refused`）。

- ユーザー名が `account_pattern` と `[A-Za-z0-9_.%-]{1,64}` に一致する。
- `'user'@'account_host'` が存在する。
- `managed_role`@`managed_role_host` が付与されており、**それ以外のロールは** 付与されていない。
- アカウントも管理対象ロールも **グローバル権限を一切** 持たない（`mysql.user` のすべての `*_priv` 列が `N` でなければならない。`SELECT ON *.*` でさえすべてのテナントに届くため）。
- どちらも動的権限（`SYSTEM_USER` を含む `mysql.global_grants`）を持たない。
- どちらも `mysql`、`sys`、`performance_schema`、`information_schema` スキーマに対する権限（`` GRANT … ON `%`.* `` や `` `m_sql`.* `` のようなワイルドカードのデータベース権限によるものを含む。`mysql.db` のデータベース名はパターンであり、tenant-pass はシステムスキーマ名をそれらと照合します）や、PROXY 権限を持たない。
- 管理対象ロールがいかなる権限も持たない（マーカーにすぎないため）。
- 管理対象ロールにロールが付与されていない。
- サーバーの `mandatory_roles` が空である（必須ロールはすべてのアカウントに適用され、アカウントごとにチェックできないため）。
- tenant-pass 自身のアカウントではない。
- レプリカの時計が、`rotation.max_clock_skew` の範囲内でサーバーの `NOW(6)` と一致している。

テナントアカウントは、自身のデータベースまたはテーブルに対する権限だけを持つことが想定されています（`GRANT … ON acme.* TO t_acme`）。

## ノードの設定

```json
{
  "name": "my1",
  "type": "mysql",
  "endpoint": {
    "address": "my1.internal:3306",
    "user": "tenant_pass_admin",
    "password_file": "/run/secrets/my1-admin-password",
    "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}
  },
  "managed_role": "tenant_pass_managed",
  "account_host": "%",
  "account_pattern": "^t_[a-z0-9_]{1,30}$",
  "connect": {"host": "my1.internal", "port": 3306, "database": "app"}
}
```

管理者接続には、実質的に TLS が必須です。暗号化されていない接続で `caching_sha2_password` の完全認証を行うには RSA 鍵交換が必要ですが、tenant-pass はそれを有効にしていません。MySQL が自動生成する証明書には、利用者のホスト名に対応する SAN がありません。適切なサーバー証明書を発行してください。

## レプリケーション

`ALTER USER` はレプリケーションされるため、ノードとして設定するのはソースだけにしてください。レプリカに接続するクライアントには、変更がレプリカに適用された時点で反映されます。新しいパスワードがレプリカで使えるようになるまでの時間には、レプリケーション遅延が加わります。

## 状態の認識

tenant-pass は `authentication_string`（プライマリ）と `User_attributes.additional_password`（セカンダリ）を読み取り、保存されているソルトでハッシュを再計算することで、自身のウィンドウを認識します。自身で計算していないメタデータは一切信頼しません。
