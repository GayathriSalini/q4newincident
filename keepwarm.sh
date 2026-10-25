#!/usr/bin/env bash
# Pings the Render service so the free instance never sleeps while you are testing. Stop it with: pkill -f keepwarm.sh
URL="${1:-https://q4newincident.onrender.com/health}"
while true; do
  code=$(curl -s -m 60 -o /dev/null -w '%{http_code} %{time_total}s' "$URL"); echo "$(date -u +%H:%M:%S) $code"
  sleep 240
done
