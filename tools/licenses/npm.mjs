import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
const read = (p) => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n').trim()
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex')
export function collectNpm(root) {
const allowed = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD', 'ISC'])
const entries = new Map()
function add(name, version, license, source, files) {
  if (!version || !source || !allowed.has(license)) throw Error(`Unreviewed license: ${name} ${license}`)
  if (!files.some((f) => /licen[cs]e|copying/i.test(f.name)) || files.some((f) => f.text.length < 30)) {
    throw Error(`Missing license text: ${name}`)
  }
  files.sort((a, b) => a.name.localeCompare(b.name, 'en'))
  const entry = { name, version, license, source, files: files.map((f) => ({ ...f, sha256: hash(f.text) })) }
  const key = `${name}@${version}`
  if (entries.has(key) && JSON.stringify(entries.get(key)) !== JSON.stringify(entry)) throw Error(`Conflicting texts: ${key}`)
  entries.set(key, entry)
}
const lock = JSON.parse(read(path.join(root, 'web/package-lock.json')))
const overrides = JSON.parse(read(path.join(root, 'tools/licenses/overrides.json')))
for (const [dir, item] of Object.entries(lock.packages)) {
  if (!dir || (item.dev && !['node_modules/tailwindcss', 'node_modules/vite', 'node_modules/rolldown'].includes(dir))) continue
  const base = path.join(root, 'web', dir)
  const pkg = JSON.parse(read(path.join(base, 'package.json')))
  if (pkg.version !== item.version) throw Error(`Run npm ci: ${dir}`)
  let files = fs.readdirSync(base).filter((n) => /^(?:third[-_. ]party[-_. ])?(?:licen[cs]es?|copying|notice)(?:[._ -]|$)/i.test(n))
    .map((name) => ({ name, text: read(path.join(base, name)) }))
  const override = overrides[`${pkg.name}@${pkg.version}`]
  let source = `https://www.npmjs.com/package/${pkg.name}/v/${pkg.version}`
  if (!files.some((f) => /licen[cs]e|copying/i.test(f.name)) && override) {
    const bytes = fs.readFileSync(path.join(root, 'tools/licenses', override.file))
    if (hash(bytes) !== override.sha256) throw Error(`Override hash mismatch: ${pkg.name}`)
    files.push({ name: 'LICENSE', text: bytes.toString('utf8').replace(/\r\n/g, '\n').trim() })
    source += `\nLicense source: ${override.source}\nSource SHA-256: ${override.sha256}`
  }
  add(pkg.name, pkg.version, pkg.license, source, files)
}

return { entries, add }
}
