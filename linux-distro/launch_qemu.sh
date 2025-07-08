#!/bin/bash

# -enable-kvm = Use hardware acceleration.
# -m 4G = Share 4 GB RAM.
# -smp 4 = Share 4 CPU thread.

qemu-system-x86_64 -enable-kvm -m 4G -cdrom ./hardclone-arch/archlinux-2025.07.06-x86_64.iso -boot d -smp 4

