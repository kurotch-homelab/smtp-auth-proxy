import { describe, expect, it } from 'vitest'

import { formatBytes, formatDateTime, formatDetails, formatRelative } from './format'

describe('formatBytes', () => {
  it('reads the way a person would', () => {
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KiB')
    expect(formatBytes(35 * 1024 * 1024)).toBe('35 MiB')
  })
})

describe('formatDateTime', () => {
  it('handles the absent and the unparseable', () => {
    expect(formatDateTime(undefined)).toBe('—')
    // A value the Date parser rejects is shown as-is rather than as
    // "Invalid Date".
    expect(formatDateTime('not-a-date')).toBe('not-a-date')
  })
})

describe('formatRelative', () => {
  it('describes the near past and future', () => {
    // The output is localized, so the assertion has to be locale-independent:
    // compare against what Intl itself produces for the same interval.
    const minuteWord = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(
      5,
      'minute',
    )
    const soon = new Date(Date.now() + 5 * 60 * 1000 + 500).toISOString()
    expect(formatRelative(soon)).toBe(minuteWord)

    expect(formatRelative(undefined)).toBe('—')
    expect(formatRelative('not-a-date')).toBe('not-a-date')
  })
})

describe('formatDetails', () => {
  it('pretty-prints JSON and leaves everything else alone', () => {
    expect(formatDetails('{"a":1}')).toBe('{\n  "a": 1\n}')
    expect(formatDetails('not json')).toBe('not json')
  })
})
