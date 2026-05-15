import { useEffect, useState, useCallback } from 'react'
import {
  Stack,
  Title,
  Card,
  Text,
  Button,
  Group,
  SimpleGrid,
  TextInput,
  Badge,
  Divider,
  Loader,
  Center,
  Avatar,
  ActionIcon,
} from '@mantine/core'
import { IconUsers, IconPlus, IconLogout, IconPlayerPlay, IconRefresh } from '@tabler/icons-react'
import { useNavigate } from 'react-router-dom'
import { notifications } from '@mantine/notifications'
import { api } from '../api'

export function LobbiesPage() {
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)

  const fetchLobbies = useCallback(async () => {
    try {
      const d = await api.lobbies()
      setData(d)
    } catch (err) {
      notifications.show({ title: 'Error', message: 'Failed to fetch lobbies', color: 'red' })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchLobbies()
  }, [fetchLobbies])

  useEffect(() => {
    if (!data?.current_lobby) return
    const lobbyId = data.current_lobby.id
    const interval = setInterval(async () => {
      try {
        const s = await api.lobbyStatus(lobbyId)
        if (s.active !== 0) {
          navigate('/game')
        }
      } catch {
        // ignore polling errors
      }
    }, 500)
    return () => clearInterval(interval)
  }, [data, navigate])

  const handleCreate = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    try {
      await api.createLobby(name.trim())
      setName('')
      await fetchLobbies()
      notifications.show({ title: 'Lobby created', message: name, color: 'green' })
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to create lobby', color: 'red' })
    } finally {
      setCreating(false)
    }
  }

  const handleJoin = async (id) => {
    try {
      await api.joinLobby(id)
      await fetchLobbies()
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to join lobby', color: 'red' })
    }
  }

  const handleStart = async () => {
    try {
      await api.startGame()
      navigate('/game')
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to start game', color: 'red' })
    }
  }

  const handleLeave = async () => {
    try {
      await api.leaveLobby()
      await fetchLobbies()
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to leave lobby', color: 'red' })
    }
  }

  if (loading) {
    return (
      <Center h="50vh">
        <Loader />
      </Center>
    )
  }

  const currentLobby = data?.current_lobby
  const isHost = currentLobby && data.username === currentLobby.username

  return (
    <Stack gap="xl">
      {currentLobby && (
        <Card withBorder padding="lg" radius="md" shadow="sm">
          <Stack gap="md">
            <Group justify="space-between">
              <Group gap="sm">
                <Title order={3}>{currentLobby.name}</Title>
                <Badge color="violet" variant="light">
                  Your lobby
                </Badge>
                {isHost && <Badge color="grape">Host</Badge>}
              </Group>
              <Group gap="xs">
                {isHost && (
                  <Button
                    leftSection={<IconPlayerPlay size={16} />}
                    color="green"
                    onClick={handleStart}
                  >
                    Start Game
                  </Button>
                )}
                <Button
                  leftSection={<IconLogout size={16} />}
                  variant="light"
                  color="red"
                  onClick={handleLeave}
                >
                  Leave
                </Button>
              </Group>
            </Group>
            <Divider />
            <Stack gap="xs">
              <Text fw={500} c="dimmed" size="sm">
                Players ({data.players_in_lobby.length})
              </Text>
              <Group gap="sm">
                {data.players_in_lobby.map((p) => (
                  <Group key={p.username} gap="xs">
                    <Avatar color="violet" radius="xl" size="sm">
                      {p.username[0]?.toUpperCase()}
                    </Avatar>
                    <Text size="sm">{p.username}</Text>
                  </Group>
                ))}
              </Group>
            </Stack>
          </Stack>
        </Card>
      )}

      <Stack gap="md">
        <Group justify="space-between">
          <Title order={2}>Available Lobbies</Title>
          <ActionIcon variant="subtle" onClick={fetchLobbies} aria-label="Refresh">
            <IconRefresh size={20} />
          </ActionIcon>
        </Group>

        {data?.lobbies?.length ? (
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
            {data.lobbies.map((l) => (
              <Card key={l.id} withBorder padding="lg" radius="md">
                <Stack gap="sm">
                  <Group justify="space-between">
                    <Title order={4}>{l.name}</Title>
                    <IconUsers size={20} color="var(--mantine-color-dimmed)" />
                  </Group>
                  <Text c="dimmed" size="sm">
                    Created by {l.username}
                  </Text>
                  <Button
                    variant="light"
                    onClick={() => handleJoin(l.id)}
                    disabled={currentLobby?.id === l.id}
                    fullWidth
                  >
                    {currentLobby?.id === l.id ? 'Already in this lobby' : 'Join'}
                  </Button>
                </Stack>
              </Card>
            ))}
          </SimpleGrid>
        ) : (
          <Card withBorder padding="xl" radius="md">
            <Text ta="center" c="dimmed">
              No lobbies available yet. Be the first to create one.
            </Text>
          </Card>
        )}
      </Stack>

      <Card withBorder padding="lg" radius="md" shadow="sm">
        <form onSubmit={handleCreate}>
          <Stack gap="md">
            <Title order={3}>Create new lobby</Title>
            <TextInput
              label="Lobby name"
              placeholder="Enter a name..."
              value={name}
              onChange={(e) => setName(e.currentTarget.value)}
              required
            />
            <Group>
              <Button
                type="submit"
                leftSection={<IconPlus size={16} />}
                loading={creating}
                disabled={!name.trim()}
              >
                Create lobby
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>
    </Stack>
  )
}
