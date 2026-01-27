#!/usr/bin/env bash
set -euo pipefail

# Create one or more patch files in the repository `patches/` directory
# Usage: patches/create_patch.sh <file> [...]

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [ $# -lt 1 ]; then
  echo "Usage: $0 <file>..."
  exit 2
fi

ts=$(date +%Y%m%d-%H%M%S)
mkdir -p patches

for f in "$@"; do
  if [ ! -e "$f" ]; then
    echo "Skipping missing file: $f"
    continue
  fi
  safe=$(echo "$f" | sed 's|/|_|g' | sed 's|[^A-Za-z0-9._-]|_|g')
  out="patches/${ts}-${safe}.patch"
  git diff --no-prefix HEAD -- "$f" > "$out" || { rm -f "$out"; echo "No changes for $f"; continue; }
  if [ -s "$out" ]; then
    echo "Created $out"
  else
    rm -f "$out"
    echo "No changes for $f"
  fi
done
