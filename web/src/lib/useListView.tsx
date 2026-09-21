import { useSearchParams } from 'react-router-dom'
import { Button, Input } from '@/components/ui'

export function useListView<T>(items: T[] | undefined, searchable: (item: T) => string) {
  const [params, setParams] = useSearchParams()
  const search = params.get('search') ?? ''
  const page = Math.max(0, Number(params.get('page')) || 0)
  const filtered = (items ?? []).filter((item) =>
    searchable(item).toLowerCase().includes(search.toLowerCase()),
  )
  const change = (key: string, value: string) => {
    setParams((current) => {
      const next = new URLSearchParams(current)
      next.set(key, value)
      if (key !== 'page') next.delete('page')
      return next
    })
  }
  return {
    items: filtered.slice(page * 50, (page + 1) * 50),
    controls: (
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Input
          aria-label="Search connections or users"
          placeholder="Search"
          value={search}
          onChange={(e) => {
            change('search', e.target.value)
          }}
        />
        <span>{filtered.length} results</span>
        {filtered.length > 50 && (
          <>
            <Button
              disabled={page === 0}
              onClick={() => {
                change('page', String(page - 1))
              }}
            >
              Previous
            </Button>
            <span>Page {page + 1}</span>
            <Button
              disabled={(page + 1) * 50 >= filtered.length}
              onClick={() => {
                change('page', String(page + 1))
              }}
            >
              Next
            </Button>
          </>
        )}
      </div>
    ),
    detailUrl: (id: string) => {
      const next = new URLSearchParams(params)
      next.set('id', id)
      return `?${next.toString()}`
    },
  }
}
