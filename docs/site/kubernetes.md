# Kubernetes / Helm

Helm、kubectl、永続ボリュームを使えるクラスタを用意します。以下は既定 namespace に 1 レプリカ・SQLite で導入する例です。

## Secret とリリースを作成

次は Bash の例です。暗号鍵を安全に控えたうえで Secret に保存してください。

```sh
key="$(docker run --rm ghcr.io/kurotch-homelab/smtp-auth-proxy:latest genkey -quiet)"
kubectl create secret generic smtp-auth-proxy-encryption --from-literal=key="$key"
unset key
helm install smtp-auth-proxy oci://ghcr.io/kurotch-homelab/charts/smtp-auth-proxy --set encryption.existingSecret=smtp-auth-proxy-encryption
kubectl rollout status deployment/smtp-auth-proxy
kubectl exec deployment/smtp-auth-proxy -- /usr/local/bin/smtp-auth-proxy adduser --config /etc/smtp-auth-proxy/config.yaml --username admin
```

## 管理画面を開く

```sh
kubectl port-forward service/smtp-auth-proxy-admin 8080:8080
```

`http://localhost:8080` にログインします。継続運用では HTTPS の ingress を設定します。SMTP Service の既定値は `LoadBalancer` です。機器から到達できるアドレスが割り当てられているか確認します。

```sh
kubectl get service smtp-auth-proxy-smtp
```

## 本番向けの values 例

同じ namespace に TLS Secret `smtp-auth-proxy-tls` を作ってから適用します。

```yaml
encryption:
  existingSecret: smtp-auth-proxy-encryption
smtp:
  tls:
    existingSecret: smtp-auth-proxy-tls
config:
  smtp:
    hostname: smtp.example.com
    tls:
      self_signed: false
  admin:
    base_url: https://smtp-admin.example.com
```

```sh
helm upgrade smtp-auth-proxy oci://ghcr.io/kurotch-homelab/charts/smtp-auth-proxy -f values.yaml
```

利用する chart version は `--version` で固定できます。`admin.base_url` だけでは ingress は作られないため、公開方法も合わせて設定してください。

2 レプリカ以上にする場合は `database.driver: postgres` と共有 PostgreSQL の DSN Secret を指定します。SQLite のまま複数レプリカにはできません。全設定は [Helm values](https://github.com/kurotch-homelab/smtp-auth-proxy/blob/main/deploy/helm/smtp-auth-proxy/values.yaml) を参照してください。
