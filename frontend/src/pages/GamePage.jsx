import { useEffect, useRef, useState } from 'react'
import { debounce } from 'lodash'; // Import lodash for debouncing
import {
  Stack,
  Title,
  Text,
  Card,
  Textarea,
  Group,
  Badge,
  Button,
  Progress,
  Table,
  Loader,
  Center,
  Code,
  Alert,
} from '@mantine/core'
import { IconBolt, IconLogout, IconInfoCircle, IconCheck } from '@tabler/icons-react'
import { useNavigate } from 'react-router-dom'
import { notifications } from '@mantine/notifications'
import { api } from '../api'

export function GamePage() {
  const navigate = useNavigate()
  const [gameData, setGameData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [lyrics, setLyrics] = useState('')
  const [score, setScore] = useState(0)
  const [players, setPlayers] = useState([])
  const [status, setStatus] = useState(1)
  const [ready, setReady] = useState(false)
  const audioRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    api
      .game()
      .then((d) => {
        if (!cancelled) {
          setGameData(d)
          setStatus(d.lobby.active)
        }
      })
      .catch(() => {
        navigate('/lobbies')
      })
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [navigate])

  async function updateGame (lyrics, songId) {
    const res = await api.updateGame(lyrics, songId)
        setScore(res.score)
        setPlayers(res.players || [])
        setStatus(res.status)
        if (res.status === 2 && audioRef.current?.paused) {
          audioRef.current.play().catch(() => {})
        }
  }

  useEffect(() => {
    if (!gameData) return
    updateGame(lyrics, gameData.song.id) // Initial update when lyrics change
    const interval = setInterval(async () => {
      try {
        await updateGame(lyrics, gameData.song.id)
      } catch {
        // swallow polling errors
        
      }
    }, 1000)
    return () => clearInterval(interval)
  }, [lyrics])

  const handleReady = async () => {
    try {
      await api.ready()
      setReady(true)
      notifications.show({ title: 'Ready!', message: 'Waiting for other players...', color: 'green' })
    } catch {
      notifications.show({ title: 'Error', message: 'Could not send ready signal', color: 'red' })
    }
  }

  const handleLeave = async () => {
    await api.leaveLobby()
    navigate('/')
  }

  if (loading) {
    return (
      <Center h="50vh">
        <Loader />
      </Center>
    )
  }

  if (!gameData) return null

  const sortedPlayers = [...players].sort((a, b) => (b.score || 0) - (a.score || 0))

  return (
    <Stack gap="lg">
      <Card withBorder padding="lg" radius="md" shadow="sm">
        <Group justify="space-between" align="flex-start">
          <Stack gap={4}>
            <Group gap="sm">
              <Title order={2}>{gameData.song.name}</Title>
              {status === 2 ? (
                <Badge color="green" variant="filled">
                  Playing
                </Badge>
              ) : (
                <Badge color="yellow" variant="light">
                  Waiting for players
                </Badge>
              )}
            </Group>
            <Text c="dimmed">by {gameData.song.artist}</Text>
          </Stack>
          <Group>
            {!ready && status !== 2 && (
              <Button
                color="green"
                leftSection={<IconCheck size={16} />}
                onClick={handleReady}
              >
                Ready
              </Button>
            )}
            <Button
              variant="light"
              color="red"
              leftSection={<IconLogout size={16} />}
              onClick={handleLeave}
            >
              Leave
            </Button>
          </Group>
        </Group>

        <audio ref={audioRef} preload="metadata" controls={false} style={{ display: 'none' }}>
          <source src={api.songUrl(gameData.song.id)} type="audio/mpeg" />
        </audio>
      </Card>

      <Card withBorder padding="lg" radius="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Title order={4}>Your guess</Title>
            <Group gap="xs">
              <IconBolt size={18} color="var(--mantine-color-violet-5)" />
              <Text fw={600}>{score}</Text>
              <Text c="dimmed" size="sm">
                score
              </Text>
            </Group>
          </Group>
          <Progress value={Math.min(score / 5, 100)} color="violet" />
          <Textarea
            placeholder="Type the lyrics you can hear or remember..."
            value={lyrics} // Use the immediate state for the Textarea value
            onChange={e => setLyrics(e.currentTarget.value)}
            autosize
            minRows={6}
            maxRows={12}
            disabled={status !== 2 && !ready}
          />
          {status !== 2 && (
            <Alert color="yellow" icon={<IconInfoCircle size={16} />}>
              Press <strong>Ready</strong> to start. The song begins once everyone is ready.
            </Alert>
          )}
        </Stack>
      </Card>

      {gameData.is_admin && gameData.song.lyrics && (
        <Card withBorder padding="lg" radius="md">
          <Stack gap="xs">
            <Title order={5}>Admin reveal — answer lyrics</Title>
            <Code block>{gameData.song.lyrics}</Code>
          </Stack>
        </Card>
      )}

      <Card withBorder padding="lg" radius="md">
        <Stack gap="sm">
          <Title order={4}>Scoreboard</Title>
          {sortedPlayers.length ? (
            <Table verticalSpacing="sm" striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>#</Table.Th>
                  <Table.Th>Player</Table.Th>
                  <Table.Th>Score</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sortedPlayers.map((p, i) => (
                  <Table.Tr key={p.username}>
                    <Table.Td>
                      <Badge variant={i === 0 ? 'filled' : 'light'} color="violet">
                        {i + 1}
                      </Badge>
                    </Table.Td>
                    <Table.Td>{p.username}</Table.Td>
                    <Table.Td>{p.score ?? 0}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : (
            <Text c="dimmed">No scores yet.</Text>
          )}
        </Stack>
      </Card>
    </Stack>
  )
}
