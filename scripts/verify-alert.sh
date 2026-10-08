#!/usr/bin/env bash
# Run on Suricata-Sensor. Lists custom-rule alerts from eve.json.
# grep -a is required: eve.json can contain bytes that make grep report "binary file matches".
# Requires: jq
set -u

EVE=/var/log/suricata/eve.json

echo "Custom SSH alerts:"
sudo grep -a '"event_type":"alert"' "$EVE" \
  | grep -a 'CUSTOM SSH' \
  | jq -r '.timestamp + " | " + .alert.signature + " | " + .src_ip + " -> " + .dest_ip'

echo
echo "Alert counts by signature:"
sudo grep -a '"event_type":"alert"' "$EVE" | jq -r '.alert.signature' | sort | uniq -c
