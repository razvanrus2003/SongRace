import { AppShell, Group, Title, Button, Badge, Anchor, Container } from '@mantine/core'
import { IconMusic, IconLogout, IconLogin } from '@tabler/icons-react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../AuthContext'
import { api } from '../api'

export function AppLayout({ children }) {
  const { user, isAdmin } = useAuth()
  const location = useLocation()

  const navLinks = [
    { to: '/', label: 'Home', show: true },
    { to: '/lobbies', label: 'Lobbies', show: Boolean(user) },
    { to: '/library', label: 'Library', show: isAdmin() },
    { to: '/admin', label: 'Admin', show: isAdmin() },
    { to: '/user', label: 'Profile', show: Boolean(user) },
  ]

  return (
    <AppShell header={{ height: 64 }} padding="md">
      <AppShell.Header>
        <Container size="lg" h="100%">
          <Group h="100%" justify="space-between">
            <Group gap="lg">
              <Group gap="xs" component={Link} to="/" style={{ textDecoration: 'none', color: 'inherit' }}>
                <IconMusic size={28} stroke={1.8} color="var(--mantine-color-violet-5)" />
                <Title order={3}>Song Racer</Title>
              </Group>
              <Group gap="xs" visibleFrom="sm">
                {navLinks
                  .filter((l) => l.show)
                  .map((l) => (
                    <Anchor
                      key={l.to}
                      component={Link}
                      to={l.to}
                      c={location.pathname === l.to ? 'violet' : 'dimmed'}
                      fw={location.pathname === l.to ? 600 : 400}
                      underline="never"
                    >
                      {l.label}
                    </Anchor>
                  ))}
              </Group>
            </Group>
            <Group gap="sm">
              {user ? (
                <>
                  <Badge variant="light" color="violet" size="lg">
                    {user.username}
                  </Badge>
                  <Button
                    component="a"
                    href={api.logoutUrl()}
                    leftSection={<IconLogout size={16} />}
                    variant="subtle"
                    color="red"
                  >
                    Logout
                  </Button>
                </>
              ) : (
                <Button
                  component="a"
                  href={api.loginUrl()}
                  leftSection={<IconLogin size={16} />}
                >
                  Login
                </Button>
              )}
            </Group>
          </Group>
        </Container>
      </AppShell.Header>
      <AppShell.Main>
        <Container size="lg" py="md">
          {children}
        </Container>
      </AppShell.Main>
    </AppShell>
  )
}
