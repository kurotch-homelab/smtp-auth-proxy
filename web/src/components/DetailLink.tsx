import { useRestoreFocusTarget } from '@fluentui/react-components'
import { Link } from 'react-router-dom'
import type { LinkProps } from 'react-router-dom'

/** The opener remains the keyboard focus target when a detail drawer closes. */
export function DetailLink(props: LinkProps) {
  return <Link {...useRestoreFocusTarget()} {...props} />
}
