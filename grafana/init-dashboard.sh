#!/bin/bash
set -e

# Wait for Grafana to be ready
echo "Waiting for Grafana to be ready..."
for i in {1..30}; do
  if curl -s -f http://localhost:3000/api/health > /dev/null; then
    echo "Grafana is ready"
    break
  fi
  echo "Attempt $i: Grafana not ready yet, waiting..."
  sleep 1
done

# Create Prometheus datasource
echo "Creating Prometheus datasource..."
curl -s -X POST http://localhost:3000/api/datasources \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d '{
  "name": "Prometheus",
  "type": "prometheus",
  "url": "http://prometheus:9090",
  "access": "proxy",
  "isDefault": true
}' | jq . || echo "Datasource may already exist"

# Wait a moment for datasource to be registered
sleep 2

# Import dashboard
echo "Importing frontend dashboard..."
curl -s -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -u admin:admin \
  -d @/etc/grafana/provisioning/dashboards/frontend-requests.json | jq .

echo "Grafana initialization complete"
