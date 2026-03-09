#!/usr/bin/env bash
# AFO OPNsense Test VM Setup
# Downloads OPNsense and creates a QEMU/KVM VM for testing AFO integration.
set -euo pipefail

VM_DIR="${HOME}/.afo/opnsense-vm"
ISO_URL="https://mirror.ams1.nl.leaseweb.net/opnsense/releases/25.1/OPNsense-25.1-dvd-amd64.iso.bz2"
ISO_BZ2="${VM_DIR}/opnsense.iso.bz2"
ISO="${VM_DIR}/opnsense.iso"
DISK="${VM_DIR}/opnsense.qcow2"
DISK_SIZE="8G"
RAM="1024"  # 1GB - enough for testing
CPUS="2"
# Management network: host can reach OPNsense at 192.168.56.1
# WAN: uses host NAT for internet access

echo "=== AFO OPNsense Test VM Setup ==="
echo ""

mkdir -p "${VM_DIR}"

# ── Step 1: Download ISO ──
if [ -f "${ISO}" ]; then
    echo "[1/3] ISO already downloaded: ${ISO}"
else
    echo "[1/3] Downloading OPNsense 25.1 (~500MB)..."
    curl -L --progress-bar -o "${ISO_BZ2}" "${ISO_URL}"
    echo "     Decompressing..."
    bunzip2 "${ISO_BZ2}"
    echo "     Done: ${ISO}"
fi

# ── Step 2: Create disk ──
if [ -f "${DISK}" ]; then
    echo "[2/3] Disk already exists: ${DISK}"
else
    echo "[2/3] Creating ${DISK_SIZE} disk..."
    qemu-img create -f qcow2 "${DISK}" "${DISK_SIZE}"
fi

# ── Step 3: Create start/stop scripts ──
echo "[3/3] Creating VM scripts..."

cat > "${VM_DIR}/start.sh" << 'STARTEOF'
#!/usr/bin/env bash
# Start OPNsense test VM
VM_DIR="$(dirname "$(readlink -f "$0")")"
DISK="${VM_DIR}/opnsense.qcow2"
ISO="${VM_DIR}/opnsense.iso"

# Check if already running
if [ -f "${VM_DIR}/vm.pid" ] && kill -0 "$(cat "${VM_DIR}/vm.pid")" 2>/dev/null; then
    echo "VM already running (PID $(cat "${VM_DIR}/vm.pid"))"
    echo "Web UI:  https://192.168.56.2"
    echo "API:     https://192.168.56.2/api"
    exit 0
fi

BOOT_ARGS=""
if [ -f "${ISO}" ]; then
    BOOT_ARGS="-cdrom ${ISO}"
fi

echo "Starting OPNsense VM..."
echo "  RAM: 1024MB | CPUs: 2 | Disk: ${DISK}"
echo ""

qemu-system-x86_64 \
    -name "opnsense-afo" \
    -m 1024 \
    -smp 2 \
    -enable-kvm \
    -cpu host \
    -drive file="${DISK}",format=qcow2,if=virtio \
    ${BOOT_ARGS} \
    -netdev user,id=wan,net=10.0.2.0/24,dhcpstart=10.0.2.15 \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:aa:bb:01 \
    -netdev socket,id=lan,listen=:8010 \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:aa:bb:02 \
    -netdev user,id=mgmt,net=192.168.56.0/24,dhcpstart=192.168.56.2,hostfwd=tcp::10443-:443,hostfwd=tcp::10022-:22,hostfwd=tcp::10080-:80 \
    -device virtio-net-pci,netdev=mgmt,mac=52:54:00:aa:bb:03 \
    -display none \
    -daemonize \
    -pidfile "${VM_DIR}/vm.pid" \
    -serial mon:telnet:127.0.0.1:4567,server,nowait \
    -monitor unix:"${VM_DIR}/monitor.sock",server,nowait

echo "VM started!"
echo ""
echo "  Console:    telnet 127.0.0.1 4567"
echo "  Web UI:     https://localhost:10443"
echo "  SSH:        ssh -p 10022 root@localhost"
echo "  API:        https://localhost:10443/api"
echo ""
echo "  Default login: root / opnsense"
echo ""
echo "  After install, create an API key in:"
echo "    System > Access > Users > root > API keys"
echo ""
echo "  Then add to .env:"
echo "    AFO_BACKEND=opnsense"
echo "    OPNSENSE_HOST=https://localhost:10443"
echo "    OPNSENSE_API_KEY=<your-key>"
echo "    OPNSENSE_API_SECRET=<your-secret>"
STARTEOF

cat > "${VM_DIR}/stop.sh" << 'STOPEOF'
#!/usr/bin/env bash
VM_DIR="$(dirname "$(readlink -f "$0")")"
if [ -f "${VM_DIR}/vm.pid" ]; then
    PID=$(cat "${VM_DIR}/vm.pid")
    if kill -0 "${PID}" 2>/dev/null; then
        kill "${PID}"
        echo "VM stopped (PID ${PID})"
    else
        echo "VM not running"
    fi
    rm -f "${VM_DIR}/vm.pid"
else
    echo "No PID file found"
fi
STOPEOF

cat > "${VM_DIR}/console.sh" << 'CONSEOF'
#!/usr/bin/env bash
echo "Connecting to OPNsense console... (Ctrl+] to exit)"
telnet 127.0.0.1 4567
CONSEOF

chmod +x "${VM_DIR}/start.sh" "${VM_DIR}/stop.sh" "${VM_DIR}/console.sh"

echo ""
echo "=== Setup complete ==="
echo ""
echo "VM files:  ${VM_DIR}/"
echo ""
echo "Commands:"
echo "  ${VM_DIR}/start.sh    - Start the VM"
echo "  ${VM_DIR}/stop.sh     - Stop the VM"
echo "  ${VM_DIR}/console.sh  - Open serial console"
echo ""
echo "After starting, install OPNsense via the console,"
echo "then access the web UI at https://localhost:10443"
