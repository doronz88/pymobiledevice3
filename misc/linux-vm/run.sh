#!/bin/bash
# Run a command against the host's USB-attached devices from a Linux VM (Lima).
#
#   misc/linux-vm/run.sh pymobiledevice3 developer dvt ls /
#   misc/linux-vm/run.sh pytest -m device tests/services/instruments
#
# The VM is created on first use and kept for later runs (`limactl stop pmd3-linux` to stop it).
# Each run copies the working tree (uncommitted and new non-ignored files included) into the VM,
# installs it into a Python 3.15 venv (3.13+ needs no compiler: sslpsk-pmd3 is only required
# below 3.13), and forwards the host's usbmuxd socket into the VM over a dedicated SSH connection
# for the duration of the command only.
set -euo pipefail

VM="${PMD3_LINUX_VM:-pmd3-linux}"
PYTHON_VERSION="${PMD3_LINUX_VM_PYTHON:-3.15}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

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
# Lima mirrors the host uid into the guest, so the guest's runtime dir is known up front.
USBMUXD_GUEST="/run/user/$(id -u)/usbmuxd"
limactl shell "$VM" bash -euc "
    # sshd never unlinks a forwarded socket, and a stale one fails the next forward.
    rm -f $USBMUXD_GUEST
    [ -x ~/.local/bin/uv ] || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
    [ \"\$(~/venv/bin/python -c 'import sys; print(\"%d.%d\" % sys.version_info[:2])' 2>/dev/null)\" = $PYTHON_VERSION ] ||
        ~/.local/bin/uv venv -q --clear -p $PYTHON_VERSION ~/venv
    cd ~/pmd3
    SETUPTOOLS_SCM_PRETEND_VERSION_FOR_PYMOBILEDEVICE3='${version:-0.0.0}+vm' \
        ~/.local/bin/uv pip install -q -p ~/venv/bin/python '.[test]'
"

# A dedicated connection (not Lima's ControlMaster) so the forward ends with the command; the socket is
# created 0600, so only the VM user can reach the host's usbmuxd (and with it, the pair records).
tty=-T
[ -t 0 ] && [ -t 1 ] && tty=-t
# Commands run from the copied tree, so tests and misc/ scripts resolve as they do on the host.
exec ssh -F "$(limactl list --format '{{.Dir}}' "$VM")/ssh.config" -o ControlPath=none -o ExitOnForwardFailure=yes -o LogLevel=error \
    "$tty" -R "$USBMUXD_GUEST:/var/run/usbmuxd" "lima-$VM" \
    "cd ~/pmd3 && USBMUXD_SOCKET_ADDRESS=$USBMUXD_GUEST PATH=\$HOME/venv/bin:\$PATH exec $(printf '%q ' "$@")"
