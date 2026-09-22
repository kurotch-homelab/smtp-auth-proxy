# Microsoft 365 の準備

まずは標準の SMTP 転送を設定します。送信用の共有メールボックス（例: `scanner@example.com`）を作成し、Entra アプリ登録と Exchange の権限を準備してください。

## 1. Entra アプリを登録

[Microsoft Entra 管理センター](https://entra.microsoft.com)の **App registrations → New registration** で単一テナントのアプリを登録します。メール送信の client credentials flow にリダイレクト URI は不要です。

記録する値は次のとおりです。

| 値 | 確認する場所 | 用途 |
| --- | --- | --- |
| Directory (tenant) ID | アプリ登録の Overview | プロキシの Tenant ID |
| Application (client) ID | アプリ登録の Overview | プロキシの Client ID |
| Object ID | **Enterprise applications** の対象アプリ | Exchange への登録 |
| Client secret の **Value** | Certificates & secrets | プロキシのクライアントシークレット |

**App registrations の Object ID は Exchange 登録に使いません。** Secret ID と secret の Value も別物です。Value は作成直後に保管し、有効期限を記録してください。

## 2. API 権限と管理者同意

**API permissions → Add a permission → APIs my organization uses → Office 365 Exchange Online → Application permissions** で `SMTP.SendAsApp` を追加し、テナントの管理者同意を与えます。

## 3. Exchange に登録してメールボックスを許可

Exchange 管理権限のある PowerShell セッションで実行します。プレースホルダーを実際の値に置き換えてください。

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -Organization '<tenant-id>'

New-ServicePrincipal -AppId '<client-id>' -ObjectId '<enterprise-app-object-id>' -DisplayName 'smtp-auth-proxy'
$sp = Get-ServicePrincipal -Identity '<enterprise-app-object-id>'
Add-MailboxPermission -Identity 'scanner@example.com' -User $sp.Identity -AccessRights FullAccess
```

アプリ登録は共有でき、メールボックスへの許可は送信に使う各メールボックスに設定します。既に Exchange に登録済みなら `New-ServicePrincipal` を重ねて実行せず、既存の登録を確認します。SendAs を使う構成では、Microsoft の手順に従い `Add-RecipientPermission` による権限も確認してください。

管理画面の **Credentials → Setup** から値を埋めた手順も確認できます。SMTP AUTH がテナントやメールボックスのポリシーで無効になっていないかも管理者に確認します。[Microsoft の OAuth 設定手順](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)を併せて参照してください。

## 4. プロキシに登録して確認

[機器設定](./device-setup.md)の順で Credentials と Mailboxes を登録します。**Check authentication** はトークン取得の確認です。続けて **Send test email** で送信権限を含む実際の配送を確認してください。

## Graph を使う場合

Microsoft Graph の **Application permission `Mail.Send`** と管理者同意を設定し、メールボックスの Transport を `graph` にします。SMTP 用の Exchange 設定手順と混同しないでください。アプリのメールボックスアクセス範囲はテナント側でも管理します。[Microsoft Graph sendMail の仕様](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0)を参照してください。

## 基本認証の廃止予定について

本プロキシは上流に OAuth を使います。Exchange Online の基本認証廃止時期は変更されているため、古い終了日を前提にせず、[Microsoft の最新アナウンス](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835)で確認してください。
