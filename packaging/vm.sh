#!/usr/bin/env bash
# Host side of the Linux and Windows packaging: a Lima VM with Ubuntu 26.04
# builds and tests the packages. Only this repository (read-only) and dist/
# (writable) are visible to the VM.
#
#   packaging/vm.sh create          create and provision the VM (once)
#   packaging/vm.sh linux [parts]   build the Linux packages (bin flatpak snap)
#   packaging/vm.sh windows         build the Windows packages
#   packaging/vm.sh test            test what is in dist/
#   packaging/vm.sh shell           open a shell in the VM
#   packaging/vm.sh delete          remove the VM
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM="${BXPLORE_VM:-bxplore-pkg}"
mkdir -p "$ROOT/dist"
in_vm() { limactl shell "$VM" -- env DIST=/dist "$@"; }

case "${1:-}" in
  create)
    if ! limactl list -q | grep -qx "$VM"; then
      limactl create --name="$VM" --tty=false --vm-type=vz --rosetta --cpus=6 --memory=8 --disk=80 --mount-none \
        --set ".mounts=[{\"location\":\"$ROOT\",\"mountPoint\":\"/src\",\"writable\":false},{\"location\":\"$ROOT/dist\",\"mountPoint\":\"/dist\",\"writable\":true}]" \
        template://ubuntu-26.04
    fi
    limactl start "$VM" --tty=false || true
    in_vm bash /src/packaging/vm-setup.sh
    ;;
  linux) shift; in_vm bash /src/packaging/linux/build.sh "$@" ;;
  windows) in_vm bash /src/packaging/windows/build.sh ;;
  test) in_vm bash /src/packaging/test.sh ;;
  shell) limactl shell "$VM" ;;
  delete) limactl delete --force "$VM" ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
