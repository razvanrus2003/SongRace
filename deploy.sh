docker exec -it songrace-manager-1 docker stack rm songrace

docker exec songrace-manager-1 docker swarm leave --force 2>/dev/null || true
docker exec songrace-worker1-1 docker swarm leave --force 2>/dev/null || true
docker exec songrace-worker2-1 docker swarm leave --force 2>/dev/null || true

docker compose -f docker-compose.dind.yml up -d

sleep 5

MANAGER_IP=$(docker inspect songrace-manager-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
docker exec songrace-manager-1 docker swarm init --advertise-addr $MANAGER_IP

JOIN_CMD=$(docker exec songrace-manager-1 docker swarm join-token worker -q)
docker exec songrace-worker1-1 docker swarm join --token $JOIN_CMD $MANAGER_IP:2377
docker exec songrace-worker2-1 docker swarm join --token $JOIN_CMD $MANAGER_IP:2377

docker exec songrace-manager-1 docker stack deploy -c /docker-compose.yml songrace

docker exec songrace-manager-1 docker node ls
