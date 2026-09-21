import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { collectNpm } from './npm.mjs'

function fixture({ license = 'MIT', text = true, version = '1.0.0', dev = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'license-test-'))
  const pkg = path.join(root, 'web/node_modules/example')
  fs.mkdirSync(pkg, { recursive: true })
  fs.mkdirSync(path.join(root, 'tools/licenses'), { recursive: true })
  fs.writeFileSync(path.join(root, 'tools/licenses/overrides.json'), '{}')
  fs.writeFileSync(path.join(root, 'web/package-lock.json'), JSON.stringify({ packages: { 'node_modules/example': { version, dev } } }))
  fs.writeFileSync(path.join(pkg, 'package.json'), JSON.stringify({ name: 'example', version, license }))
  if (text) fs.writeFileSync(path.join(pkg, 'LICENSE'), 'Copyright Example authors\nPermission is hereby granted under the MIT license.')
  return root
}
test('collection is deterministic and includes copyright text', () => {
  const root = fixture()
  const one = [...collectNpm(root).entries.values()]
  assert.deepEqual(one, [...collectNpm(root).entries.values()])
  assert.match(one[0].files[0].text, /Copyright Example authors/)
})
test('missing body and unknown license fail closed', () => {
  assert.throws(() => collectNpm(fixture({ text: false })), /Missing license text/)
  assert.throws(() => collectNpm(fixture({ license: 'UNLICENSED' })), /Unreviewed license/)
})
test('dependency updates change the manifest', () => {
  const before = [...collectNpm(fixture()).entries.keys()]
  const after = [...collectNpm(fixture({ version: '2.0.0' })).entries.keys()]
  assert.notDeepEqual(before, after)
})
test('overrides require matching content hashes', () => {
  const root = fixture({ text: false })
  fs.writeFileSync(path.join(root, 'tools/licenses/reviewed.txt'), 'A reviewed license body')
  fs.writeFileSync(path.join(root, 'tools/licenses/overrides.json'), JSON.stringify({ 'example@1.0.0': { file: 'reviewed.txt', source: 'https://example.org/v1/LICENSE', sha256: 'wrong' } }))
  assert.throws(() => collectNpm(root), /Override hash mismatch/)
})
