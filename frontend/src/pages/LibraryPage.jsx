import { useEffect, useState, useCallback } from 'react'
import {
  Stack,
  Title,
  Text,
  Card,
  Group,
  Button,
  SimpleGrid,
  TextInput,
  Textarea,
  FileInput,
  Loader,
  Center,
  Badge,
} from '@mantine/core'
import { IconMusic, IconUpload, IconFileMusic } from '@tabler/icons-react'
import { useForm } from '@mantine/form'
import { notifications } from '@mantine/notifications'
import { api } from '../api'

export function LibraryPage() {
  const [songs, setSongs] = useState([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)

  const form = useForm({
    initialValues: { name: '', artist: '', lyrics: '', file: null },
    validate: {
      name: (v) => (v?.trim() ? null : 'Name is required'),
      artist: (v) => (v?.trim() ? null : 'Artist is required'),
      lyrics: (v) => (v?.trim() ? null : 'Lyrics are required'),
    },
  })

  const fetchSongs = useCallback(async () => {
    try {
      const d = await api.library()
      setSongs(d.songs || [])
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to load library', color: 'red' })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSongs()
  }, [fetchSongs])

  const handleSubmit = async (values) => {
    setUploading(true)
    try {
      const fd = new FormData()
      fd.append('name', values.name)
      fd.append('artist', values.artist)
      fd.append('lyrics', values.lyrics)
      if (values.file) fd.append('file', values.file)
      await api.addSong(fd)
      notifications.show({ title: 'Song added', message: values.name, color: 'green' })
      form.reset()
      await fetchSongs()
    } catch {
      notifications.show({ title: 'Error', message: 'Failed to add song', color: 'red' })
    } finally {
      setUploading(false)
    }
  }

  if (loading) {
    return (
      <Center h="50vh">
        <Loader />
      </Center>
    )
  }

  return (
    <Stack gap="xl">
      <Stack gap="md">
        <Title order={2}>Song Library</Title>
        {songs.length ? (
          <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="md">
            {songs.map((s) => (
              <Card key={s.id} withBorder padding="md" radius="md">
                <Group gap="sm" align="flex-start">
                  <IconMusic size={32} color="var(--mantine-color-violet-5)" />
                  <Stack gap={2} style={{ flex: 1 }}>
                    <Text fw={600}>{s.name}</Text>
                    {s.artist && (
                      <Text size="sm" c="dimmed">
                        {s.artist}
                      </Text>
                    )}
                    {s.filename && (
                      <Badge variant="light" size="xs" leftSection={<IconFileMusic size={10} />}>
                        {s.filename}
                      </Badge>
                    )}
                  </Stack>
                </Group>
              </Card>
            ))}
          </SimpleGrid>
        ) : (
          <Card withBorder padding="xl" radius="md">
            <Text ta="center" c="dimmed">
              The library is empty.
            </Text>
          </Card>
        )}
      </Stack>

      <Card withBorder padding="lg" radius="md" shadow="sm">
        <form onSubmit={form.onSubmit(handleSubmit)}>
          <Stack gap="md">
            <Title order={3}>Add a new song</Title>
            <Group grow>
              <TextInput
                label="Song name"
                placeholder="Bohemian Rhapsody"
                {...form.getInputProps('name')}
              />
              <TextInput
                label="Artist"
                placeholder="Queen"
                {...form.getInputProps('artist')}
              />
            </Group>
            <Textarea
              label="Lyrics"
              placeholder="Paste the full lyrics here..."
              minRows={6}
              autosize
              maxRows={14}
              {...form.getInputProps('lyrics')}
            />
            <FileInput
              label="Audio file"
              placeholder="Choose a .mp3 file"
              accept="audio/*"
              leftSection={<IconUpload size={16} />}
              {...form.getInputProps('file')}
            />
            <Group justify="flex-end">
              <Button type="submit" loading={uploading} leftSection={<IconUpload size={16} />}>
                Add Song
              </Button>
            </Group>
          </Stack>
        </form>
      </Card>
    </Stack>
  )
}
