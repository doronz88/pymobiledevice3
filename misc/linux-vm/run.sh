#!/bin/bash
# Run a command against the host's USB-attached devices from a Linux VM (Lima).
#
#   misc/linux-vm/run.sh pymobiledevice3 developer dvt ls /
#   misc/linux-vm/run.sh pytest -m device tests/services/instruments
#
# The VM is created on first use and kept for later runs (`limactl stop pmd3-linux` to stop it).
# Each run copies the working tree (uncommitted and new non-ignored files included) into the VM,
# installs it into a Python 3.13 venv (3.13 needs no compiler: sslpsk-pmd3 is only required
# below 3.13, and pylzss has no cp314 wheels yet), and exposes the host's usbmuxd to the VM on a
# loopback TCP port for the duration of the command only.
set -euo pipefail

VM="${PMD3_LINUX_VM:-pmd3-linux}"
PORT="${PMD3_LINUX_VM_USBMUX_PORT:-27015}"
PYTHON_VERSION="${PMD3_LINUX_VM_PYTHON:-3.13}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

if [ $# -eq 0 ]; then
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
command -v limactl >/dev/null || { echo "limactl not found (brew install lima)" >&2; exit 1; }

status="$(limactl list --format '{{.Status}}' "$VM" 2>/dev/null || true)"
if [ -z "$status" ]; then
    limactl start --name="$VM" --tty=false --cpus=4 --memory=4 template://ubuntu-lts
elif [ "$status" != "Running" ]; then
    limactl start --tty=false "$VM"
fi

version="$(git -C "$REPO" describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')"
git -C "$REPO" ls-files -z --cached --others --exclude-standard |
    (cd "$REPO" && python3 -I -c 'import os, sys; sys.stdout.write("".join(p + "\0" for p in sys.stdin.read().split("\0") if os.path.isfile(p)))') |
    COPYFILE_DISABLE=1 tar -C "$REPO" --no-xattrs --null -T - -cf - |
    limactl shell "$VM" bash -c 'rm -rf ~/pmd3 && mkdir ~/pmd3 && tar -xf - -C ~/pmd3'
limactl shell "$VM" bash -euc "
    [ -x ~/.local/bin/uv ] || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
    [ \"\$(~/venv/bin/python -c 'import sys; print(\"%d.%d\" % sys.version_info[:2])' 2>/dev/null)\" = $PYTHON_VERSION ] ||
        ~/.local/bin/uv venv -q --clear -p $PYTHON_VERSION ~/venv
    cd ~/pmd3
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYMOBILEDEVICE3='${version:-0.0.0}+vm' \
        ~/.local/bin/uv pip install -q -p ~/venv/bin/python '.[test]'
"

python3 -I "$HERE/usbmux_tcp.py" "$PORT" &
forwarder=$!
trap 'kill $forwarder 2>/dev/null' EXIT
for _ in $(seq 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
    sleep 0.1
done

# Commands run from the copied tree, so tests and misc/ scripts resolve as they do on the host.
limactl shell --workdir /tmp "$VM" bash -c \
    "cd ~/pmd3 && USBMUXD_SOCKET_ADDRESS=host.lima.internal:$PORT PATH=\$HOME/venv/bin:\$PATH exec \"\$@\"" \
    bash "$@"
