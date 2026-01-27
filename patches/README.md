# Patches directory

Place generated diff-format patch files here. Two helper scripts are provided:

- `create_patch.sh <file>...` — create patch files from working-tree changes (uses `git diff`).
- `apply_patches.sh [patch1.patch ...]` — apply patches using `git apply --index` (applies all `patches/*.patch` when run without args).

Usage examples:

```bash
# Make changes to src/mctp_control.c then create a patch for it
./patches/create_patch.sh src/mctp_control.c

# Apply all patches in patches/
./patches/apply_patches.sh

# Or apply a single patch
./patches/apply_patches.sh patches/20260126-123456-src_mctp_control.c.patch
```

Notes:
- The scripts expect to be run from anywhere inside the git repository; they discover the repo root automatically.
- Make the scripts executable if needed: `chmod +x patches/*.sh`.

- A convenience wrapper is available: `scripts/west_update_apply.sh` — run this instead of `west update` to automatically apply patches after update.
- To optionally install git hooks that attempt to apply patches on merges/checkouts, run `scripts/install_hooks.sh` (this modifies your local `.git/hooks`).
