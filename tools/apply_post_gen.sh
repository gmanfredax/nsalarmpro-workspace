#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
project_root="$(cd "$script_dir/.." && pwd)"

if [ -f "$project_root/NSAlarmPro.ioc" ]; then
  echo "NSAlarmPro project ready"
fi
