const API_BASE = '/api'

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    ...options,
  })

  if (res.status === 401) {
    const err = new Error('unauthorized')
    err.status = 401
    throw err
  }
  if (res.status === 403) {
    const err = new Error('forbidden')
    err.status = 403
    throw err
  }
  if (!res.ok) {
    const err = new Error(`request_failed_${res.status}`)
    err.status = res.status
    throw err
  }

  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return res.json()
  }
  return res
}

function postJson(path, body) {
  return request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

export const api = {
  me: () => request('/me'),
  loginUrl: () => `${API_BASE}/login`,
  logoutUrl: () => `${API_BASE}/logout`,

  lobbies: () => request('/lobbies'),
  createLobby: (name) => postJson('/lobby/create', { name }),
  joinLobby: (id) => postJson(`/lobby/join/${id}`),
  lobbyStatus: (id) => request(`/lobby/status/${id}`),
  leaveLobby: () => postJson('/lobby/leave'),

  startGame: () => postJson('/game/start'),
  ready: () => postJson('/game/ready'),
  updateGame: (lyrics, songId) => postJson('/game/update', { lyrics, songId }),
  game: () => request('/game'),
  songUrl: (id) => `${API_BASE}/get_song/${id}`,

  library: () => request('/library'),
  addSong: (formData) =>
    request('/add_song', { method: 'POST', body: formData }),

  clearLobbies: () => postJson('/lobbies/clear'),
  clearPlayers: () => postJson('/players/clear'),
}
