import { collectNpm } from './npm.mjs'
// Run from any directory after `npm ci` in web. No network license fallbacks:
// missing texts must be reviewed and pinned in overrides.json.
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const read = (p) => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n').trim()
const run = (exe, args, env = {}) => execFileSync(exe, args, {
  cwd: root, env: { ...process.env, GOTOOLCHAIN: 'go1.27.0', ...env }, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
})
const { entries, add } = collectNpm(root)

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'smtp-licenses-'))
const toolVersion = read(path.join(root, 'Makefile')).match(/GOLICENSES_VERSION\s*:?=\s*(\S+)/)?.[1]
if (!toolVersion) throw Error('Missing pinned go-licenses version')
run('go', ['install', `github.com/google/go-licenses/v2@${toolVersion}`], { GOBIN: temp })
const tool = path.join(temp, process.platform === 'win32' ? 'go-licenses.exe' : 'go-licenses')
const modules = [...run('go', ['list', '-m', '-json', 'all']).matchAll(/\{[\s\S]*?\n\}/g)]
  .map((m) => JSON.parse(m[0])).sort((a, b) => b.Path.length - a.Path.length)
const own = 'github.com/kurotch-homelab/smtp-auth-proxy'
for (const target of ['linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64']) {
  const [GOOS, GOARCH] = target.split('/')
  const env = { GOOS, GOARCH, CGO_ENABLED: '0' }
  // Resolve first: go-licenses must never mistake a failed package load for an empty dependency set.
  run('go', ['list', '-deps', './cmd/smtp-auth-proxy'], env)
  const args = ['./cmd/smtp-auth-proxy', `--ignore=${own}`]
  const report = run(tool, ['report', ...args], env).trim()
  if (!report) throw Error(`Empty Go license report: ${target}`)
  const saved = path.join(temp, `${GOOS}-${GOARCH}`)
  run(tool, ['save', ...args, `--save_path=${saved}`], env)
  for (const row of report.split('\n')) {
    const [rawName, rawSource, license] = row.trim().split(',')
    const name = rawName.replaceAll('\\', '/')
    const source = rawSource.replaceAll('\\', '/')
    const mod = modules.find((m) => name === m.Path || name.startsWith(`${m.Path}/`))
    const base = path.join(saved, name)
    const files = fs.readdirSync(base).filter((n) => fs.statSync(path.join(base, n)).isFile())
      .map((name) => ({ name, text: read(path.join(base, name)) }))
    add(name, mod?.Version, license, source, files)
  }
}
// Standard library licenses are not collected by go-licenses. Use the same
// pinned compiler as CI and release builds.
const goVersion = run('go', ['env', 'GOVERSION']).trim().replace(/^go/, '')
add('Go runtime and standard library', goVersion, 'BSD-3-Clause',
  'https://go.dev/LICENSE', [{ name: 'LICENSE', text: read(path.join(run('go', ['env', 'GOROOT']).trim(), 'LICENSE')) }])
const goroot = run('go', ['env', 'GOROOT']).trim()
for (const lib of ['crypto', 'net', 'sys', 'text']) {
  const license = path.join(goroot, 'src/vendor/golang.org/x', lib, 'LICENSE')
  if (!fs.existsSync(license)) throw Error(`Missing Go vendor license: ${lib}`)
  add(`Go standard library vendored golang.org/x/${lib}`, goVersion, 'BSD-3-Clause',
    `https://github.com/golang/go/blob/go${goVersion}/src/vendor/golang.org/x/${lib}/LICENSE`, [{ name: 'LICENSE', text: read(license) }])
}
const sorted = [...entries.values()].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`, 'en'))
const manifest = JSON.stringify(sorted.map((e) => ({ ...e, files: e.files.map(({ name, sha256 }) => ({ name, sha256 })) })), null, 2) + '\n'
const notices = ['smtp-auth-proxy — distribution notices', read(path.join(root, 'NOTICE')), read(path.join(root, 'LICENSE')),
  ...sorted.map((e) => [`${e.name} ${e.version}`, `License: ${e.license}`, `Source: ${e.source}`,
    ...e.files.map((f) => `--- ${f.name} ---\n${f.text}`)].join('\n\n'))].join('\n\n' + '='.repeat(78) + '\n\n') + '\n'
for (const [name, contents] of [['THIRD_PARTY_NOTICES.txt', notices], ['manifest.json', manifest]]) {
  const dest = path.join(root, 'internal/legal', name)
  if (process.argv.includes('--check')) {
    if (!fs.existsSync(dest) || fs.readFileSync(dest, 'utf8').replace(/\r\n/g, '\n') !== contents) throw Error(`Stale ${name}: run node tools/licenses/generate.mjs`)
  } else {
    fs.mkdirSync(path.dirname(dest), { recursive: true })
    fs.writeFileSync(dest, contents)
  }
}
console.log(`Verified notices for ${sorted.length} dependencies.`)
