import '@testing-library/jest-dom/vitest'
import { beforeEach, vi } from 'vitest'

// JSDOM has no layout observer. Fluent uses it to reflow message bars;
// responsive layout itself is checked in the browser.
beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe = vi.fn()
      unobserve = vi.fn()
      disconnect = vi.fn()
    },
  )
})
