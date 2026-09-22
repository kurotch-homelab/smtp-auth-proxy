---
layout: home
hero:
  name: smtp-auth-proxy
  text: いつもの機器から、Microsoft 365 へ。
  tagline: プリンター・NAS・監視システムの SMTP 認証を、OAuth 2.0 に橋渡しするリレー。導入から最初の送信、日々の運用まで。
  actions:
    - theme: brand
      text: Docker Compose で始める
      link: /getting-started
    - theme: alt
      text: Microsoft 365 を設定する
      link: /microsoft-365
features:
  - title: 機器ごとのアカウント
    details: SMTP ユーザーと送信元メールボックスを対応付け、機器単位でパスワードやアクセスを管理します。
  - title: キューで配送を管理
    details: 受信したメールを保存し、上流の一時障害時は再試行。管理画面から状態とエラーを確認できます。
  - title: SMTP と Graph に対応
    details: Microsoft 365 への送信方式をメールボックスごとに選択。機器側はユーザー名とパスワードの SMTP 認証を使えます。
---

## どうつながる？

```text
プリンター / NAS / 監視システム
  │ SMTP AUTH（ユーザー名・パスワード + STARTTLS）
  ▼
smtp-auth-proxy ── キュー保存・送信元制御・再試行
  │ OAuth 2.0（アプリケーション認証）
  ▼
Microsoft 365（SMTP XOAUTH2 または Microsoft Graph）
  ▼
受信者
```

このサイトは使い方のドキュメントです。SMTP サーバーと管理画面は、利用者の Docker ホストまたは Kubernetes クラスタで動かします。

## 最初の送信まで

1. [プロキシを起動し、管理者を作成する](./getting-started.md)。
2. [Entra アプリと送信用メールボックスを準備する](./microsoft-365.md)。
3. [Credentials → Mailboxes → SMTP accounts の順に登録する](./device-setup.md)。
4. [管理画面と実機の両方から送信を確認する](./operations.md)。

本ガイドはリポジトリの `main` の機能を説明します。利用中のリリースが古い場合は、画面や診断機能が異なることがあります。[リリース一覧](https://github.com/kurotch-homelab/smtp-auth-proxy/releases)も確認してください。
