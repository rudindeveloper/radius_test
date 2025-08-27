#!/bin/bash
set -e

echo "Stopping and removing existing radius-server container..."
CONTAINER_ID=$(docker ps -a -q -f name=radius-server)
if [ ! -z "$CONTAINER_ID" ]; then
    docker stop $CONTAINER_ID
    docker rm $CONTAINER_ID
fi

echo "Building the radius-server image..."
docker build -t radius-server .

echo "Starting the radius-server container..."
docker run -d -p 1812:1812/udp --name radius-server radius-server

echo
echo "Server started successfully."
