import { Center, Loader, Stack, Text, Button } from '@mantine/core'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../AuthContext'
import { api } from '../api'

export function RequireAuth({ children, role }) {
  const { user, loading, hasRole } = useAuth()

  if (loading) {
    return (
      <Center h="60vh">
        <Loader />
      </Center>
    )
  }

  if (!user) {
    return (
      <Center h="60vh">
        <Stack align="center" gap="md">
          <Text>You need to be logged in to view this page.</Text>
          <Button component="a" href={api.loginUrl()}>
            Login with Keycloak
          </Button>
        </Stack>
      </Center>
    )
  }

  if (role && !hasRole(role) && !hasRole('admin')) {
    return <Navigate to="/denied" replace />
  }

  return children
}
