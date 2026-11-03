# PostgreSQL

[English](../../en/stores/postgres.md)

## 仕組み

各テナントは `LOGIN` ロールです。ウィンドウ `n` について、tenant-pass は `pg_advisory_xact_lock` を保持したトランザクション内で次を実行します。

```sql
ALTER ROLE "t_acme" PASSWORD 'SCRAM-SHA-256$4096:…' VALID UNTIL '2026-11-03 12:13:59+00';
```

- 送信されるのは SCRAM-SHA-256 ベリファイアだけです。平文のパスワードがサーバーに届くことはありません。
- `VALID UNTIL` は PostgreSQL 自身が強制します。それを過ぎると、tenant-pass が停止していても、そのパスワードでは新規接続を開けません。
- 既存の接続は、変更や失効の影響を受けません。
- ロールが持てるパスワードは 1 つなので、tenant-pass が次のウィンドウに切り替えると（`refresh_at` から。別のレプリカの時計がわずかに進んでいれば数秒早まる可能性があります）、以前のパスワードは **その `expires_at` に達していなくても** 新規接続には使えなくなります。PostgreSQL の認証情報では `refresh_at` を実質的な終了時刻として扱い、`28P01` のときは 1 回リトライしてください（[クライアント連携](../client-integration.md) を参照）。

## 対応バージョン

PostgreSQL **16 以降**（実行時に強制されます）。PostgreSQL 16 で `CREATEROLE` の仕様が変わり、管理者が `ADMIN OPTION` を持つロールにのみ適用されるようになりました。16 より前では、`CREATEROLE` を持つロールは任意の非スーパーユーザーロールのパスワードを変更でき、またロールは自身へのメンバーシップを他のロールに付与できるため、あるテナントが別のテナントのロールを tenant-pass のメンバーシップチェックに失敗させることができてしまいます。

`password_encryption` は `scram-sha-256`（14 以降のデフォルト）でなければならず、`pg_hba.conf` はテナントロールに対して `scram-sha-256` を使わなければなりません。

## セットアップ（PostgreSQL 16 以降）

スーパーユーザー（またはプロビジョニング用のロール）で実行します。

```sql
-- tenant-pass's own database. tenant-pass serializes work on each role
-- with advisory locks, which are scoped to one database: if tenants could
-- connect to it, any tenant could hold another tenant's lock and block its
-- rotation. tenant-pass refuses to work in a database that PUBLIC or any
-- managed role may connect to.
CREATE DATABASE tenant_pass;
REVOKE ALL ON DATABASE tenant_pass FROM PUBLIC;

-- The account tenant-pass logs in as.
CREATE ROLE tenant_pass_admin LOGIN CREATEROLE PASSWORD '<random>';
GRANT CONNECT ON DATABASE tenant_pass TO tenant_pass_admin;

-- Marker: tenant-pass only touches members of this role.
CREATE ROLE tenant_pass_managed NOLOGIN;
```

テナントごとに次を実行します（プロビジョニングプロセスが行います）。

```sql
CREATE ROLE t_acme LOGIN IN ROLE tenant_pass_managed;
-- Let tenant-pass change t_acme's password, without being able to act as t_acme:
GRANT t_acme TO tenant_pass_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
-- Then grant t_acme what the tenant needs, e.g.:
-- CREATE SCHEMA acme AUTHORIZATION t_acme;
```

注記:

- `tenant_pass_admin` 自身がテナントロールを作成する場合、PostgreSQL 16 以降では `ADMIN OPTION` が自動的に付与されます（`INHERIT`/`SET` の有無は `createrole_self_grant` によります。この設定は空のままにしてください）。
- `INHERIT FALSE, SET FALSE` により、`tenant_pass_admin` は **デフォルトでは** テナントの権限を使えません。これは強固な境界ではありません。`ADMIN OPTION` を持つ管理者は、`SET TRUE` 付きでそのロールを自身に付与し直すことができます。tenant-pass が決してこれを行うことはありませんが、`tenant_pass_admin` のログインを掌握した者なら可能です。このアカウントはそれに見合った方法で保護してください。
- テナントロールに `SUPERUSER`、`CREATEROLE`、`CREATEDB`、`REPLICATION`、`BYPASSRLS` を与えないでください。いずれにせよ tenant-pass はそのようなロールを拒否します。
- tenant-pass はトランザクションプーラーを経由せず、PostgreSQL に直接接続してください。

サーバーの TLS: tenant-pass が使うアドレスに一致する SAN を持つ証明書で `ssl = on` を設定し（または `tls.server_name` を設定し）、CA を `tls.ca_file` に指定してください。

## 安全性チェック

アドバイザリーロックの下で、変更を加える前に、tenant-pass は `pg_roles` / `pg_auth_members` を読み取り、次の条件をすべて満たさない限り拒否します（監査ログに `account_refused`）。

- ロール名が `account_pattern` に一致する。
- ロールが存在し、`LOGIN` を持つ。
- `managed_group` のメンバーである（`pg_has_role(role, group, 'MEMBER')`）。
- `SUPERUSER`、`CREATEROLE`、`CREATEDB`、`REPLICATION`、`BYPASSRLS` のいずれも持たない。
- 直接的または間接的にメンバーとなっているどのロールも、これらの属性のいずれかを持たず、定義済みの `pg_*` ロール（`pg_read_all_data`、`pg_write_server_files`、`pg_execute_server_program` など）でもなく、ログインもできない。
- そのロール自身も、それがメンバーとなっているどのロールも、いかなるロールに対しても `ADMIN OPTION` を持たない。
- `managed_group` そのものでも、tenant-pass 自身のログインロールでもない。

また、自身の時計をサーバーの `clock_timestamp()` と比較し、差が `rotation.max_clock_skew` を超える場合は書き込みを拒否します。さらに、サーバーが PostgreSQL 16 以降であり、かつ管理者接続のデータベースに PUBLIC もどの管理対象ロールも接続できない場合を除き、一切の処理を拒否します。

テナントロールには、自身のオブジェクトに対する権限を（または特別な属性を持たない NOLOGIN のグループロールを通じて）付与してください。それより広いものは拒否されます。

## ノードの設定

```json
{
  "name": "pg1",
  "type": "postgres",
  "endpoint": {
    "address": "pg1.internal:5432",
    "user": "tenant_pass_admin",
    "password_file": "/run/secrets/pg1-admin-password",
    "database": "tenant_pass",
    "tls": {"ca_file": "/etc/tenant-pass/db-ca.pem"}
  },
  "managed_group": "tenant_pass_managed",
  "account_pattern": "^t_[a-z0-9_]{1,40}$",
  "connect": {"host": "pgbouncer.internal", "port": 6432, "database": "app"}
}
```

## PgBouncer

クライアントは PgBouncer を経由して接続できます。要件は次のとおりです。

- 静的な `userlist.txt` **ではなく**、`auth_type = scram-sha-256` と `auth_query`（`SECURITY DEFINER` 関数を通じて `pg_shadow` を参照する）を使ってください。そうすれば、PgBouncer は常に現在のベリファイアに対して照合します。
- `server_reset_query = DISCARD ALL` のままにしてください。
- すでに開いているサーバー接続は、ローテーション後も使い続けられます。

## 状態の認識

tenant-pass は、自身が設定したウィンドウを `rolvaliduntil` から認識します。tenant-pass が設定するのは常に、そのロールのウィンドウ境界と正確に一致する値だけです。`NULL`、`infinity`、その他の値は「まだ管理されていない」ことを意味し、上書きされます。`VALID UNTIL` はそのままで、パスワードだけが手作業で変更された場合、クライアントは `28P01` を受け取り、`repair: true` でリトライし、tenant-pass が（同一の）ベリファイアを書き直します。

## ロギング

送信されるのはベリファイアだけですが、tenant-pass からの DDL がログに記録されないよう、`ALTER ROLE tenant_pass_admin SET log_statement = 'none'`（スーパーユーザー権限が必要）の設定を検討してください。
