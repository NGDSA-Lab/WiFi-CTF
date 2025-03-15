#!/bin/bash
set -e

POOL_FILE="/tmp/wifi_pool.txt"
COUNTER_FILE="/tmp/container_counter.txt"

# Initialize the pool file if it doesn't exist: numbers 1 to 60 (for phy1 to phy60)
if [ ! -f "$POOL_FILE" ]; then
    seq 1 60 > "$POOL_FILE"
fi

# Initialize the container counter if it doesn't exist
if [ ! -f "$COUNTER_FILE" ]; then
    echo 1 > "$COUNTER_FILE"
fi

# Check that there are at least 3 available radios
AVAILABLE_COUNT=$(wc -l < "$POOL_FILE")
if [ "$AVAILABLE_COUNT" -lt 3 ]; then
    echo "Error: Not enough available radios. Need 3 available, have $AVAILABLE_COUNT."
    exit 1
fi

# Read the first 3 available radio numbers from the pool
AP_PHY=$(head -n 1 "$POOL_FILE")
CLIENT_PHY=$(sed -n '2p' "$POOL_FILE")
EXTRA_PHY=$(sed -n '3p' "$POOL_FILE")

# Remove the first 3 lines from the pool file
tail -n +4 "$POOL_FILE" > "${POOL_FILE}.tmp" && mv "${POOL_FILE}.tmp" "$POOL_FILE"

# Get container counter and increment it
CONTAINER_NUM=$(cat "$COUNTER_FILE")
NEW_CONTAINER_NUM=$((CONTAINER_NUM + 1))
echo "$NEW_CONTAINER_NUM" > "$COUNTER_FILE"

CONTAINER_NAME="container${CONTAINER_NUM}"
# Use a dynamic host port
HOST_PORT=$((2220 + CONTAINER_NUM))

echo "[*] Launching container ${CONTAINER_NAME} with host port ${HOST_PORT}"
echo "[*] Assigned radios: AP_PHY=phy${AP_PHY}, CLIENT_PHY=phy${CLIENT_PHY}, EXTRA_PHY=phy${EXTRA_PHY}"

# Start the container with entrypoint.sh as its main command
docker run -d --privileged --name "$CONTAINER_NAME" -p ${HOST_PORT}:22 \
    -e AP_PHY="${AP_PHY}" -e CLIENT_PHY="${CLIENT_PHY}" -e EXTRA_PHY="${EXTRA_PHY}" \
    -e AP_IF="wlan1" -e CLIENT_IF="wlan2" -e EXTRA_IF="wlan3" \
    ngdsa-wifi-ctf

# Allow a moment for the container to start
sleep 1

# Retrieve the container's PID from Docker
PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_NAME")
echo "[*] Container PID: $PID"

if [ "$PID" -eq 0 ]; then
    echo "Error: Container PID is 0. The container may have crashed."
    # Return radios back to pool.
    echo "$AP_PHY" >> "$POOL_FILE"
    echo "$CLIENT_PHY" >> "$POOL_FILE"
    echo "$EXTRA_PHY" >> "$POOL_FILE"
    exit 1
fi

# Move the assigned physical wireless interfaces from the host into the container's network namespace
sudo iw phy phy${AP_PHY} set netns $PID
sudo iw phy phy${CLIENT_PHY} set netns $PID
sudo iw phy phy${EXTRA_PHY} set netns $PID

# Signal the container that radios are moved
docker exec "$CONTAINER_NAME" touch /tmp/radios_ready

# Launch a background process to monitor container termination and perform cleanup
(
    docker wait "$CONTAINER_NAME" > /dev/null
    echo "[*] Container $CONTAINER_NAME terminated. Returning radios to pool."
    # Append the used radios back to the pool
    echo "$AP_PHY" >> "$POOL_FILE"
    echo "$CLIENT_PHY" >> "$POOL_FILE"
    echo "$EXTRA_PHY" >> "$POOL_FILE"
    sort -n "$POOL_FILE" -o "$POOL_FILE"
    echo "[*] Cleanup completed for $CONTAINER_NAME."
) &

echo "[*] Container $CONTAINER_NAME started."
