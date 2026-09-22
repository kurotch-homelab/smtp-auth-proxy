# Docker Compose で導入する

Docker / Docker Compose、Git、Microsoft 365 の送信用メールボックスを用意します。Entra と Exchange の権限設定にはテナント管理者の協力が必要です。

## 1. 設定ファイルを取得

```sh
git clone https://github.com/kurotch-homelab/smtp-auth-proxy.git
cd smtp-auth-proxy/deploy/compose
cp .env.example .env
```

以降は `deploy/compose` で実行します。配布構成では SMTP が TCP 587、管理画面が TCP 8080、保存先が Docker の `data` ボリュームです。

## 2. 暗号鍵を生成

```sh
docker run --rm ghcr.io/kurotch-homelab/smtp-auth-proxy:latest genkey -quiet
```

出力された鍵全体を `.env` の `SMTP_AUTH_PROXY_ENCRYPTION_KEY=` の右側に貼り付けます。鍵は保存済み OAuth シークレットの復号に必要です。`.env` を Git に登録せず、データと一緒に安全にバックアップしてください。

## 3. 起動と初期管理者の作成

```sh
docker compose up -d
docker compose ps
docker compose logs --tail=100 proxy
docker compose exec proxy /usr/local/bin/smtp-auth-proxy adduser --config /etc/smtp-auth-proxy/config.yaml --username admin
```

表示される管理者パスワードを保存し、ホスト上のブラウザーで `http://localhost:8080` を開きます。別の端末からは `http://<Docker ホストの IP>:8080` を使います。この管理者と、後で機器に設定する SMTP アカウントは別です。

## 4. TLS と接続範囲を設定

初期構成の SMTP は STARTTLS 必須で、起動時に自己署名証明書を生成します。継続運用には機器が信頼する証明書を用意してください。例えば `tls/` を Compose の volume に追加します。

```yaml
# docker-compose.yml の services.proxy.volumes に追加
- ./tls:/etc/smtp-auth-proxy/tls:ro
```

`config.yaml` の `smtp.tls` を置き換えます。

```yaml
smtp:
  # 既存の hostname / listeners は残す
  tls:
    self_signed: false
    cert_file: /etc/smtp-auth-proxy/tls/tls.crt
    key_file: /etc/smtp-auth-proxy/tls/tls.key
```

設定後に `docker compose restart proxy` を実行します。ファイルを読むコンテナユーザーに鍵の読み取り権限が必要です。管理画面を LAN 外から使う場合は HTTPS のリバースプロキシを置きます。ファイアウォールで SMTP と管理画面の接続元を必要な範囲に絞ってください。

## 5. 送信を設定

[Microsoft 365 の準備](./microsoft-365.md)を済ませ、[機器設定](./device-setup.md)に進みます。コンテナが起動しただけではメールは送れません。

## 更新・停止

バックアップ後、利用するイメージのバージョンを確認して更新します。本番では `latest` の代わりにリリースタグを固定すると更新内容を管理しやすくなります。

```sh
docker compose pull
docker compose up -d
```

停止は `docker compose down` です。`down -v` は保存ボリュームも削除するため、データを残す運用では使いません。
