#!/usr/bin/env bash
set -euo pipefail

# Apply patch files from `patches/` into the working tree using `git apply --index`
# Usage: patches/apply_patches.sh [patch1.patch patch2.patch ...]

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

if [ $# -eq 0 ]; then
  mapfile -t files < <(printf "%s\n" patches/*.patch 2>/dev/null)
else
  files=("$@")
fi

if [ ${#files[@]} -eq 0 ]; then
  echo "No patch files found in patches/"
  exit 1
fi

for p in "${files[@]}"; do
  if [ ! -f "$p" ]; then
    echo "No patch file: $p"
    continue
  fi

  if git apply --index "$p" 2>/dev/null; then
    echo "Applied $p"
    continue
  fi

  echo "git apply --index failed for $p - attempting fallback (apply then add)"

  # Detect absolute path prefixes in the patch header. If the patch targets
  # the Zephyr workspace (common when diffing against /.../zephyr/...),
  # rewrite paths and apply the patch in that workspace.
  # grab the first --- and +++ lines if present
  oldpath=$(awk '/^--- /{print $2; exit}' "$p" || true)
  newpath=$(awk '/^\+\+\+ /{print $2; exit}' "$p" || true)

  # normalize by removing surrounding quotes
  oldpath=${oldpath#\"}
  oldpath=${oldpath%\"}
  newpath=${newpath#\"}
  newpath=${newpath%\"}

  # If either path references the Zephyr workspace, pick that as target
  target_dir=""
  if [ -n "${ZEPHYR_BASE:-}" ] && (echo "$oldpath" | grep -q "${ZEPHYR_BASE}" || echo "$newpath" | grep -q "${ZEPHYR_BASE}"); then
    target_dir="$ZEPHYR_BASE"
  elif echo "$oldpath" | grep -q "zephyrproject/zephyr" || echo "$newpath" | grep -q "zephyrproject/zephyr"; then
    target_dir="/home/doug/zephyrproject/zephyr"
  fi

  if [ -n "$target_dir" ]; then
    tmppatch=$(mktemp)
    # strip absolute prefixes so paths become relative to the target workspace
    sed "s|$target_dir/||g; s|/home/doug/git/iot-foundry-zephyr-endpoint/||g; s|/home/doug/zephyrproject/zephyr/||g" "$p" > "$tmppatch"
    # ensure new-file path in the patch matches the existing path in the target
    old_rel=$(echo "$oldpath" | sed "s|$target_dir/||g; s|/home/doug/git/iot-foundry-zephyr-endpoint/||g; s|/home/doug/zephyrproject/zephyr/||g")
    # If the resolved path doesn't exist in the target, try common alternates
    if [ ! -e "$target_dir/$old_rel" ]; then
      if [ -e "$target_dir/subsys/$old_rel" ]; then
        old_rel="subsys/$old_rel"
      else
        base=$(basename "$old_rel")
        found=$(find "$target_dir" -type f -name "$base" -print -quit || true)
        if [ -n "$found" ]; then
          # make old_rel relative to target_dir
          old_rel=${found#"$target_dir/"}
        fi
      fi
    fi

    sed -E -i "s|^(\+\+\+ )\S+|\1${old_rel}|" "$tmppatch"
    if git -C "$target_dir" apply --index "$tmppatch" 2>/dev/null; then
      # stage affected files in the target repo
      awk '/^\+\+\+ /{print $2} /^--- /{print $2}' "$tmppatch" \
        | sed 's|a/||;s|b/||;s|/dev/null||g' \
        | sed 's|^"||;s|"$||' \
        | grep -v '^$' \
        | while read -r fp; do
          fp=$(echo "$fp" | sed 's|^[ab]/||')
          if [ -e "$target_dir/$fp" ]; then
            git -C "$target_dir" add -- "$fp" || true
          fi
        done
    else
      echo "git apply failed; trying 'patch' in $target_dir"
      if (cd "$target_dir" && patch -p0 < "$tmppatch"); then
        awk '/^\+\+\+ /{print $2} /^--- /{print $2}' "$tmppatch" \
          | sed 's|a/||;s|b/||;s|/dev/null||g' \
          | sed 's|^"||;s|"$||' \
          | grep -v '^$' \
          | while read -r fp; do
            fp=$(echo "$fp" | sed 's|^[ab]/||')
            if [ -e "$target_dir/$fp" ]; then
              git -C "$target_dir" add -- "$fp" || true
            fi
          done
      else
        echo "Failed to apply patch in $target_dir" >&2
      fi
    fi
    rm -f "$tmppatch"
    echo "Applied (to $target_dir) $p"
  else
    # default fallback: apply in this repo and stage touched files
    git apply "$p"
    awk '/^\+\+\+ /{print $2} /^--- /{print $2}' "$p" \
      | sed 's|a/||;s|b/||;s|/dev/null||g' \
      | sed 's|^"||;s|"$||' \
      | grep -v '^$' \
      | while read -r fp; do
        fp=$(echo "$fp" | sed 's|^[ab]/||')
        if [ -e "$fp" ]; then
          git add -- "$fp" || true
        fi
      done
    echo "Applied (fallback) $p"
  fi
done
