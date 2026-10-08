#!/usr/bin/env bash
# Run from Kali-Attacker. Sends 8 SSH login attempts with a wrong password
# against Ubuntu-Victim to cross the Suricata threshold (5 SYNs / 120 s / source).
# Use a real account name: a non-existent user hits a different Wazuh rule path.
# Requires: sshpass (sudo apt install sshpass)
set -u

TARGET="${1:-10.10.10.151}"
USER_NAME="${2:-ozzy7}"

for i in {1..8}; do
  sshpass -p 'wrongpass' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    "${USER_NAME}@${TARGET}" exit
done
