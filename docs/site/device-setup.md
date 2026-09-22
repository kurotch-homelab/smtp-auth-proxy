# SMTP アカウントと機器設定

管理画面に管理者としてサインインし、次の順番で登録します。

## 1. Credentials — Microsoft 365 のアプリ認証

Tenant ID、Client ID、クライアントシークレットを登録します。有効期限も入力しておくと更新時期を確認できます。1 つの credential を複数のメールボックスで共有できます。

## 2. Mailboxes — 送信元のメールボックス

`scanner@example.com` などのアドレス、先ほどの credential、Transport（`smtp` または `graph`）を選択します。詳細の **Diagnostics** で認証確認とテスト送信を行います。

## 3. SMTP accounts — 機器用のログイン

`svc-scanner` など機器専用のユーザー名で作成し、利用を許可するメールボックスを選びます。生成されたパスワードをその場で保存してください。後から元のパスワードは表示できません。

| 項目 | 設定の考え方 |
| --- | --- |
| Mailboxes this account may send as | この機器が使うメールボックスだけを選択 |
| Default mailbox | 複数ある場合の既定のメールボックスを明示 |
| Sender policy | 通常は `reject`。From を変更できない機器は `rewrite` を検討 |
| Additional allowed senders | 必要な追加送信元だけを登録。上流の SendAs 権限も別途必要 |
| Allowed networks | 機器の接続元を CIDR で指定（例: `192.168.10.25/32`） |

`passthrough` は From をそのまま上流に渡す設定です。Microsoft 365 側でその送信元が許可されている必要があります。

## 4. プリンター・NAS などに入力

| 機器の設定欄 | 入力例 |
| --- | --- |
| SMTP サーバー | プロキシの LAN 向けホスト名または IP |
| ポート | `587` |
| 暗号化 | STARTTLS |
| SMTP 認証 | 有効（LOGIN / PLAIN） |
| ユーザー名 | `svc-scanner` |
| パスワード | SMTP accounts で発行したパスワード |
| 送信元メールアドレス | `scanner@example.com` |

Microsoft 365 のパスワードや管理画面のパスワードは入力しません。証明書検証を行う機器には、プロキシの証明書を信頼させ、証明書と一致するホスト名を設定します。

## 5. 機器からテスト送信

機器のテスト機能で、管理できる宛先に 1 通送信します。管理画面の **Messages** で送信元・宛先を検索し、状態を確認してください。`sent` は上流への引き渡し成功です。受信箱・迷惑メール・Microsoft 365 のメッセージ追跡でも着信を確認します。

管理画面からのテストメールは機器の SMTP ログインを経由しません。最終確認は必ず実機から行います。
