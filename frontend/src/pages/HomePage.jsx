import { Card, Stack, Title, Text, Button, Group, SimpleGrid, ThemeIcon, Badge } from '@mantine/core'
import {
  IconUsersGroup,
  IconBook,
  IconUserShield,
  IconUserCircle,
  IconLogin,
  IconMusic,
} from '@tabler/icons-react'
import { Link, useSearchParams } from 'react-router-dom'
import { useEffect } from 'react'
import { notifications } from '@mantine/notifications'
import { useAuth } from '../AuthContext'
import { api } from '../api'

function ActionCard({ icon, title, description, to }) {
  return (
    <Card component={Link} to={to} withBorder padding="lg" radius="md" shadow="sm" style={{ textDecoration: 'none', color: 'inherit' }}>
      <Stack gap="sm">
        <ThemeIcon variant="light" size={48} radius="md" color="violet">
          {icon}
        </ThemeIcon>
        <Title order={4}>{title}</Title>
        <Text c="dimmed" size="sm">
          {description}
        </Text>
      </Stack>
    </Card>
  )
}

export function HomePage() {
  const { user, isAdmin } = useAuth()
  const [params, setParams] = useSearchParams()

  useEffect(() => {
    if (params.get('error') === 'login_failed') {
      notifications.show({
        title: 'Login failed',
        message: 'Could not complete authentication. Please try again.',
        color: 'red',
      })
      params.delete('error')
      setParams(params, { replace: true })
    }
  }, [params, setParams])

  if (!user) {
    return (
      <Stack align="center" gap="xl" mt="xl">
        <ThemeIcon size={96} radius="xl" variant="gradient" gradient={{ from: 'violet', to: 'grape' }}>
          <IconMusic size={56} />
        </ThemeIcon>
        <Stack align="center" gap="xs">
          <Title order={1}>Welcome to Song Racer</Title>
          <Text c="dimmed" size="lg" maw={520} ta="center">
            Race against friends to recall song lyrics. Sign in with your account to get started.
          </Text>
        </Stack>
        <Button
          component="a"
          href={api.loginUrl()}
          size="lg"
          leftSection={<IconLogin size={20} />}
        >
          Login with Keycloak
        </Button>
      </Stack>
    )
  }

  return (
    <Stack gap="xl">
      <Stack gap="xs">
        <Group gap="sm">
          <Title order={1}>Welcome back, {user.username}</Title>
        </Group>
        <Group gap="xs">
          <Text c="dimmed">Roles:</Text>
          {user.roles?.length ? (
            user.roles.map((r) => (
              <Badge key={r} variant="light" color={r === 'admin' ? 'red' : 'violet'}>
                {r}
              </Badge>
            ))
          ) : (
            <Badge variant="light" color="gray">
              No roles
            </Badge>
          )}
        </Group>
      </Stack>

      <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
        <ActionCard
          icon={<IconUsersGroup size={28} />}
          title="Lobbies"
          description="Join an existing lobby or create your own to start a new race."
          to="/lobbies"
        />
        <ActionCard
          icon={<IconUserCircle size={28} />}
          title="Profile"
          description="View your user dashboard."
          to="/user"
        />
        {isAdmin() && (
          <>
            <ActionCard
              icon={<IconBook size={28} />}
              title="Library"
              description="Manage the song library — add new tracks and lyrics."
              to="/library"
            />
            <ActionCard
              icon={<IconUserShield size={28} />}
              title="Admin"
              description="Administration panel for managing lobbies and players."
              to="/admin"
            />
          </>
        )}
      </SimpleGrid>
    </Stack>
  )
}
