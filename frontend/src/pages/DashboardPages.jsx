import { Stack, Title, Text, Card, Button, Group, Badge, Alert } from '@mantine/core'
import { IconUserShield, IconUserCircle, IconTrash, IconInfoCircle } from '@tabler/icons-react'
import { useState } from 'react'
import { notifications } from '@mantine/notifications'
import { useAuth } from '../AuthContext'
import { api } from '../api'

export function UserDashboardPage() {
  const { user } = useAuth()
  return (
    <Stack gap="lg">
      <Group gap="sm">
        <IconUserCircle size={32} color="var(--mantine-color-violet-5)" />
        <Title order={2}>User Dashboard</Title>
      </Group>
      <Card withBorder padding="lg" radius="md">
        <Stack gap="sm">
          <Text size="lg">
            Welcome, <strong>{user?.username}</strong>!
          </Text>
          <Group gap="xs">
            <Text c="dimmed">Email:</Text>
            <Text>{user?.email ?? '—'}</Text>
          </Group>
          <Group gap="xs">
            <Text c="dimmed">Roles:</Text>
            {user?.roles?.map((r) => (
              <Badge key={r} variant="light">
                {r}
              </Badge>
            ))}
          </Group>
        </Stack>
      </Card>
    </Stack>
  )
}

export function AdminDashboardPage() {
  const { user } = useAuth()
  const [busy, setBusy] = useState(false)

  const clearLobbies = async () => {
    setBusy(true)
    try {
      await api.clearLobbies()
      notifications.show({ title: 'Cleared', message: 'All lobbies removed', color: 'green' })
    } catch {
      notifications.show({ title: 'Error', message: 'Could not clear lobbies', color: 'red' })
    } finally {
      setBusy(false)
    }
  }

  const clearPlayers = async () => {
    setBusy(true)
    try {
      await api.clearPlayers()
      notifications.show({ title: 'Cleared', message: 'All players removed', color: 'green' })
    } catch {
      notifications.show({ title: 'Error', message: 'Could not clear players', color: 'red' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Stack gap="lg">
      <Group gap="sm">
        <IconUserShield size={32} color="var(--mantine-color-red-5)" />
        <Title order={2}>Admin Dashboard</Title>
      </Group>
      <Card withBorder padding="lg" radius="md">
        <Stack gap="sm">
          <Text size="lg">
            Welcome, <strong>{user?.username}</strong>.
          </Text>
          <Alert color="yellow" icon={<IconInfoCircle size={16} />}>
            Use the actions below to reset application state. These are destructive.
          </Alert>
          <Group>
            <Button
              color="red"
              variant="light"
              leftSection={<IconTrash size={16} />}
              onClick={clearLobbies}
              loading={busy}
            >
              Clear all lobbies
            </Button>
            <Button
              color="red"
              variant="light"
              leftSection={<IconTrash size={16} />}
              onClick={clearPlayers}
              loading={busy}
            >
              Clear all players
            </Button>
          </Group>
        </Stack>
      </Card>
    </Stack>
  )
}

export function AccessDeniedPage() {
  return (
    <Stack align="center" gap="md" mt="xl">
      <Title order={1}>Access Denied</Title>
      <Text c="dimmed">You don't have permission to view this page.</Text>
      <Button component="a" href="/">
        Return Home
      </Button>
    </Stack>
  )
}
