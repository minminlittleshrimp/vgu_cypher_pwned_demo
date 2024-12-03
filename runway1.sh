#!/bin/bash

# Set variables for image and container name
IMAGE_NAME="runway1"
CONTAINER_NAME="runway1_ctf"
PORT=1338

# Step 1: Build the Docker image
echo "[+] Building Docker image..."
docker build -qt $IMAGE_NAME ./host

# Step 2: Stop and remove any existing container (if running)
echo "[+] Stopping and removing any existing container..."
docker stop $CONTAINER_NAME 2>/dev/null
docker rm $CONTAINER_NAME 2>/dev/null

# Step 3: Run the Docker container
echo "[+] Running Docker container..."
docker run --privileged -d --name $CONTAINER_NAME -p 127.0.0.1:$PORT:$PORT $IMAGE_NAME

# Step 4: Verify that the container is running
echo "[+] Verifying the container is running..."
docker ps | grep $CONTAINER_NAME

# Step 5: Display instructions
echo "[+] Docker container is up and running!"
echo "You can connect using: nc localhost $PORT"
echo "To stop the service, run: docker stop $CONTAINER_NAME"

# Exit the script
exit 0
