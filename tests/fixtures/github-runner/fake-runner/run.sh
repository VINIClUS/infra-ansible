#!/usr/bin/env bash
set -euo pipefail

trap 'exit 0' INT TERM
while true; do
  sleep 60 &
  wait $!
done
