import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'ja-JP',
  title: 'smtp-auth-proxy',
  description: 'Microsoft 365 と LAN 機器をつなぐ SMTP リレーの導入・運用ガイド',
  cleanUrls: false,
  lastUpdated: true,
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }]],
  sitemap: { hostname: 'https://smtp-auth-proxy.pages.silver-vine.jp' },
  themeConfig: {
    siteTitle: 'smtp-auth-proxy',
    nav: [{ text: '利用ガイド', link: '/getting-started' }],
    sidebar: [
      { text: 'はじめに', items: [
        { text: '概要', link: '/' },
        { text: 'Docker Compose で導入', link: '/getting-started' },
        { text: 'Microsoft 365 の準備', link: '/microsoft-365' },
        { text: 'SMTP アカウントと機器設定', link: '/device-setup' },
      ] },
      { text: '運用する', items: [
        { text: '管理画面・配送の確認', link: '/operations' },
        { text: '設定・バックアップ・SSO', link: '/configuration' },
        { text: 'Kubernetes / Helm', link: '/kubernetes' },
        { text: 'トラブルシューティング', link: '/troubleshooting' },
      ] },
    ],
    search: { provider: 'local' },
    outline: { label: 'このページ', level: [2, 3] },
    docFooter: { prev: '前へ', next: '次へ' },
    lastUpdated: { text: '最終更新' },
    editLink: {
      pattern: 'https://github.com/kurotch-homelab/smtp-auth-proxy/edit/main/docs/site/:path',
      text: 'GitHub でこのページを編集',
    },
    socialLinks: [{ icon: 'github', link: 'https://github.com/kurotch-homelab/smtp-auth-proxy' }],
    footer: { message: 'Apache-2.0 · smtp-auth-proxy 利用ガイド' },
  },
})
