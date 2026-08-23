import { render, screen } from '@testing-library/react'

import { App } from './App'

describe('App', () => {
  it('renders the application name', () => {
    render(<App />)
    expect(screen.getByRole('heading', { name: 'smtp-auth-proxy' })).toBeInTheDocument()
  })
})
