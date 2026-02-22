#!/usr/bin/env bash
set -euo pipefail

# Enable unattended-upgrades on Ubuntu/Debian.
# Safe default: install + enable security updates.

sudo apt update
sudo apt install -y unattended-upgrades apt-listchanges

# Enable automatic security updates
sudo dpkg-reconfigure --priority=low unattended-upgrades

echo "OK. Check config at: /etc/apt/apt.conf.d/50unattended-upgrades"
