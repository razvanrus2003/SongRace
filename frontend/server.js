import express from 'express'
import fs from 'node:fs'
import path from 'node:path'
import client from 'prom-client'

const app = express()
const port = Number(process.env.PORT || 3001)
const distDir = path.resolve(process.cwd(), 'dist')

const register = new client.Registry()
client.collectDefaultMetrics({ register })

const requestCounter = new client.Counter({
  name: 'frontend_http_requests_total',
  help: 'Total number of frontend HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register],
})

const requestDuration = new client.Histogram({
  name: 'frontend_http_request_duration_seconds',
  help: 'Frontend HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
  registers: [register],
})

app.use((req, res, next) => {
  const end = requestDuration.startTimer()

  res.on('finish', () => {
    const route = req.path === '/' ? 'root' : req.path
    requestCounter.inc({ method: req.method, route, status: String(res.statusCode) })
    end({ method: req.method, route, status: String(res.statusCode) })
  })

  next()
})

app.get('/metrics', async (_req, res) => {
  res.set('Content-Type', register.contentType)
  res.end(await register.metrics())
})

app.use(express.static(distDir))

app.use((_req, res) => {
  const indexFile = path.join(distDir, 'index.html')
  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile)
  }

  return res.status(500).send('frontend build output not found')
})

app.listen(port, '0.0.0.0', () => {
  console.log(`Frontend server listening on port ${port}`)
})