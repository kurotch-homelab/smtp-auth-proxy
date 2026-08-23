/** Formatting helpers shared across the screens. */

/** Formats a timestamp for display, or a dash when there is none. */
export function formatDateTime(value: string | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

/**
 * Formats a timestamp as a rough interval from now, which is what an operator
 * watching a queue actually wants to know.
 */
export function formatRelative(value: string | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value

  const seconds = Math.round((date.getTime() - Date.now()) / 1000)

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.35],
    ['month', 12],
    ['year', Number.POSITIVE_INFINITY],
  ]

  let remaining = seconds
  for (const [unit, step] of units) {
    if (Math.abs(remaining) < step) {
      return new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(
        Math.round(remaining),
        unit,
      )
    }
    remaining /= step
  }
  return date.toLocaleString()
}

/** Formats a byte count the way a person would read it. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${String(bytes)} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit] ?? 'GiB'}`
}

/** Pretty-prints the JSON an audit entry carries, leaving anything else alone. */
export function formatDetails(details: string): string {
  try {
    return JSON.stringify(JSON.parse(details) as unknown, null, 2)
  } catch {
    return details
  }
}
