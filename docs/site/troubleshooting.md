# トラブルシューティング

**機器 → プロキシ → OAuth → Microsoft 365 → 受信者** の順に切り分けます。

## SMTP に接続できない

プロキシの TCP 587、Docker の公開ポート、Kubernetes Service、ファイアウォールを確認します。STARTTLS 前には AUTH が提示されない構成が既定です。機器の暗号化方式と証明書の信頼を確認してください。

## プロキシが認証・送信を拒否する

| エラー | 確認すること |
| --- | --- |
| プロキシから `535` | SMTP accounts のユーザー名・パスワード、有効状態、接続元ネットワーク制限 |
| `550 5.7.1` | 送信元 From と許可されたメールボックス、追加送信元、Sender policy |
| `552` | `storage.max_message_size` とメールのエンコード後のサイズ |

管理画面にログインできるパスワードでも、SMTP 認証には使えません。

## キューに入るが届かない

Messages の詳細で最後のエラーを確認します。

| エラー・症状 | 対処 |
| --- | --- |
| Exchange から `535 5.7.3` | Enterprise applications の Object ID、`SMTP.SendAsApp` の管理者同意、Exchange でのサービスプリンシパル登録、メールボックス権限、SMTP AUTH ポリシーを確認 |
| `AADSTS7000215` / `invalid_client` | Client secret の Value と有効期限を確認して更新 |
| `AADSTS90002` | Tenant ID と Authority host を確認 |
| `4.7.500 Server busy` | 同一メールボックスを使う他の送信元も含めて流量を確認し、レートを下げる |
| `550 5.7.60 SendAsDenied` | メールボックスと送信元の関係、Exchange の SendAs 権限を確認 |

認証確認が成功しても、送信権限や実際の配送は未確認です。**Send test email** で確認し、続けて実機から送信してください。`sent` なのに見つからない場合は、迷惑メール、隔離、受信者アドレス、Microsoft 365 のメッセージ追跡を確認します。

## 管理画面に入れない

ローカル認証が有効なら、新しい管理者を CLI で作成できます。

```sh
docker compose exec proxy /usr/local/bin/smtp-auth-proxy adduser --config /etc/smtp-auth-proxy/config.yaml --username rescue
```

SSO のループは `admin.base_url` と IdP の callback URI を確認します。`sso_no_role` は claim と `role_mappings` / `default_role` の不一致を確認してください。

## ログとヘルスチェック

```sh
docker compose logs --tail=200 proxy
docker compose exec proxy /usr/local/bin/smtp-auth-proxy healthcheck --url http://127.0.0.1:8080/readyz
```

メッセージ ID で配送処理を追います。必要なら `log.level: debug` を設定して再起動します。ログを共有する際はメールアドレスや本文などの個人情報を確認してください。
