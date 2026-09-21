import { Children, Fragment, isValidElement } from 'react'
import type { ReactNode, MouseEventHandler } from 'react'
import { Menu, MenuTrigger, MenuPopover, MenuList, MenuItem } from '@fluentui/react-components'
import { Button } from './ui'

interface Action {
  children?: ReactNode
  onClick?: MouseEventHandler<HTMLDivElement>
  disabled?: boolean
  busy?: boolean
}
export function ActionsMenu({ children }: { children: ReactNode }) {
  function items(nodes: ReactNode): ReactNode {
    return Children.map(nodes, (node) => {
      if (!isValidElement<Action>(node)) return null
      if (node.type === Fragment) return items(node.props.children)
      return (
        <MenuItem disabled={node.props.disabled || node.props.busy} onClick={node.props.onClick}>
          {node.props.children}
        </MenuItem>
      )
    })
  }
  const content = items(children)
  if (Children.toArray(content).length === 0) return null
  return (
    <Menu>
      <MenuTrigger disableButtonEnhancement>
        <Button variant="ghost">Actions</Button>
      </MenuTrigger>
      <MenuPopover>
        <MenuList>{content}</MenuList>
      </MenuPopover>
    </Menu>
  )
}
