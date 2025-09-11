#!/usr/bin/env bash
set -euo pipefail
repo_root_flag="${1:-tatou/flag}"
container_flag_host="${2:-/srv/tatou/flags/app.flag}"
mr_important="${3:-/srv/tatou/storage/files/Mr Important.pdf}"
new_sha=$(openssl rand -hex 20) # 40 hex chars
echo "$new_sha" > "$repo_root_flag"
echo "$new_sha" > "$container_flag_host"
if [ -f "$mr_important" ]; then
  sed -i "s/FLAG{[^}]*}/FLAG{$new_sha}/g" "$mr_important" || true
fi
echo "Rotated flags to: $new_sha"
