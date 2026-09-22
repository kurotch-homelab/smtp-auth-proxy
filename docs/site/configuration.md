# 設定・バックアップ・SSO

## 設定は 2 か所

| 設定 | 保存場所 | 反映方法 |
| --- | --- | --- |
| ポート、TLS、DB、暗号鍵、管理画面、キュー | `config.yaml` | ファイル編集後に再起動 |
| Credentials、Mailboxes、SMTP accounts、Users | DB | 管理画面から変更 |

全項目は [config.example.yaml](https://github.com/kurotch-homelab/smtp-auth-proxy/blob/main/config.example.yaml) を参照してください。

Compose で設定を変更した後は、起動前チェックも実行できます。

```sh
docker compose run --rm proxy serve --config /etc/smtp-auth-proxy/config.yaml --check
docker compose restart proxy
```

## 環境変数・Secret ファイル

```yaml
encryption:
  keys: ['${SMTP_AUTH_PROXY_ENCRYPTION_KEY}']
database:
  driver: postgres
  dsn: ${file:/run/secrets/database-dsn}
```

`${VAR}` は未定義だとエラー、`${VAR:-default}` は既定値付き、`${file:/path}` はファイルから読み取ります。Compose の `.env` は置いただけでは全項目がコンテナに渡るわけではありません。独自変数は `environment`、ファイルは `volumes` 等で渡してください。

## バックアップと暗号鍵

DB、暗号鍵、静的設定、必要なら本文 spool をまとめて復元できるようにします。既定の `storage.blob: db` は本文も DB 内に保存します。`fs` を選ぶ場合は `storage.spool_dir` もバックアップ対象です。

SQLite はプロキシを停止してから DB を含むボリュームをバックアップすると整合性を確保しやすくなります。PostgreSQL は DB のバックアップ手段を使います。暗号鍵が失われると DB だけでは保存済みシークレットを復号できません。復元手順は別環境で確認してください。

暗号鍵をローテーションするときは、新しい鍵を先頭に置き、古い鍵も残します。

```yaml
encryption:
  keys:
    - ${NEW_KEY}
    - ${OLD_KEY}
```

既存値は編集時に新しい鍵で暗号化されます。旧鍵で暗号化された値が残っている間は、旧鍵を削除しません。

## GitOps で初期データを管理する {#bootstrap}

```yaml
bootstrap:
  mode: apply-once
  path: /etc/smtp-auth-proxy/bootstrap.yaml
```

`apply-once` は初期データを投入し、その後は UI で管理します。`reconcile` は起動時ごとにファイルを再適用し、宣言された項目を UI では読み取り専用にします。`off` は無効です。

ファイル例と `smtp-auth-proxy passwd` で生成するパスワードハッシュの扱いは、[詳細な bootstrap 設定](https://github.com/kurotch-homelab/smtp-auth-proxy/blob/main/docs/configuration.md#bootstrap-gitops)を参照してください。ファイル更新だけでは常時同期されず、再起動時に適用されます。

## 管理画面の SSO

`admin.oidc` に issuer、client ID、client secret、ロールマッピングを設定し、`admin.base_url` をブラウザーが使う HTTPS の origin に合わせます。IdP に登録するリダイレクト URI は次の形式です。

```text
https://<管理画面のホスト>/api/v1/auth/oidc/callback
```

ロールの claim と `role_mappings` が一致しない場合、`default_role` が空ならログインは拒否されます。メール送信用の Entra アプリ認証と、管理画面用の OIDC ログインは別の設定です。

## PostgreSQL へ切り替える

Compose の `.env` に `POSTGRES_PASSWORD` を設定し、`config.yaml` の `database` を `driver: postgres` と `dsn: ${DATABASE_URL}` に変更します。

```sh
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
```

これは既存 SQLite のデータ移行ではありません。DB の切り替えとデータ移行は別に計画してください。複数レプリカは PostgreSQL を使います。
