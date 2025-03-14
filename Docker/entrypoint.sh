#!/bin/bash
set -e

echo "[*] Waiting for physical radios to be moved..."
while [ ! -f /tmp/radios_ready ]; do
    sleep 1
done
rm -f /tmp/radios_ready
echo "[*] Detected radios are in place. Continuing configuration..."

# Use environment variables for PHY assignments
: ${AP_PHY:="1"}
: ${CLIENT_PHY:="2"}
: ${EXTRA_PHY:="3"}

# Fixed interface names to be used inside the container
: ${AP_IF:="wlan1"}
: ${CLIENT_IF:="wlan2"}
: ${EXTRA_IF:="wlan3"}

# Set AP_SSID from environment
: ${AP_SSID:="Virtual Wifi"}
echo "[*] Setting virtual AP SSID to ${AP_SSID}..."

# Update hostapd configuration with the new SSID
sed -i "s/^ssid=.*/ssid=${AP_SSID}/" /etc/hostapd/wpa-psk.conf

# Update wpa_supplicant configuration so that the client connects to the same SSID
sed -i "s/^ *ssid=.*/  ssid=\"${AP_SSID}\"/" /etc/wpa_supplicant_wpa.conf

# Create two network namespaces. One for the AP and one for the client
ip netns add wifi_master || true
ip netns add wifi_client || true

# Spawn dummy processes in each namespace to obtain valid PIDs.
ip netns exec wifi_master bash -c "sleep infinity" &
AP_PID=$!
ip netns exec wifi_client bash -c "sleep infinity" &
CLIENT_PID=$!

sleep 1

echo "[*] wifi_master dummy PID: $AP_PID"
echo "[*] wifi_client dummy PID: $CLIENT_PID"

# Move the assigned physical radios into the appropriate namespaces
echo "[*] Moving phy${AP_PHY} to wifi_master namespace..."
iw phy phy${AP_PHY} set netns $AP_PID

echo "[*] Moving phy${CLIENT_PHY} to wifi_client namespace..."
iw phy phy${CLIENT_PHY} set netns $CLIENT_PID

echo "[*] Moving extra phy${EXTRA_PHY} to container's default namespace..."
iw phy phy${EXTRA_PHY} set netns $$

# In wifi_master namespace, determine the wireless interface and rename it
AP_IF_CURR=$(ip netns exec wifi_master iw dev | awk '/Interface/ {print $2; exit}')
if [ -z "$AP_IF_CURR" ]; then
    echo "Error: Could not determine interface in wifi_master namespace."
    exit 1
fi
echo "[*] Renaming interface in wifi_master from $AP_IF_CURR to ${AP_IF}..."
ip netns exec wifi_master ip link set "$AP_IF_CURR" name ${AP_IF}

# In wifi_client namespace, determine the wireless interface and rename it
CLIENT_IF_CURR=$(ip netns exec wifi_client iw dev | awk '/Interface/ {print $2; exit}')
if [ -z "$CLIENT_IF_CURR" ]; then
    echo "Error: Could not determine interface in wifi_client namespace."
    exit 1
fi
echo "[*] Renaming interface in wifi_client from $CLIENT_IF_CURR to ${CLIENT_IF}..."
ip netns exec wifi_client ip link set "$CLIENT_IF_CURR" name ${CLIENT_IF}

# For the extra PHY in the default namespace, find its interface
EXTRA_IF_DEFAULT=$(iw dev | awk -v phy="${EXTRA_PHY}" '$0 ~ "phy#"phy {getline; if ($1=="Interface") print $2; exit}')
if [ -z "$EXTRA_IF_DEFAULT" ]; then
    echo "Error: Could not determine interface name for phy${EXTRA_PHY}"
    exit 1
fi
echo "[*] Renaming extra PHY interface from $EXTRA_IF_DEFAULT to ${EXTRA_IF}..."
ip link set "$EXTRA_IF_DEFAULT" down
ip link set "$EXTRA_IF_DEFAULT" name ${EXTRA_IF}
ip link set ${EXTRA_IF} up

# Update hostapd configuration to use the fixed AP interface
echo "[*] Configuring hostapd to use interface ${AP_IF}..."
sed -i "s/^interface=.*/interface=${AP_IF}/" /etc/hostapd/wpa-psk.conf

# Start hostapd in the AP namespace
echo "[*] Starting hostapd in wifi_master namespace..."
ip netns exec wifi_master hostapd /etc/hostapd/wpa-psk.conf -B

# Start wpa_supplicant in the client namespace
echo "[*] Starting wpa_supplicant in wifi_client namespace..."
ip netns exec wifi_client wpa_supplicant -B -i ${CLIENT_IF} -c /etc/wpa_supplicant_wpa.conf

echo "[*] Starting SSH server..."
exec /usr/sbin/sshd -D
