#!/usr/bin/env bash
# Install Claude Code memory files from the repo to the local machine.
# Run once on a new machine after git clone/pull:
#   ./install_memory.sh

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
# Claude Code memory path is based on the repo's absolute path with / replaced by -
ESCAPED="$(echo "$REPO_DIR" | sed 's|^/||; s|/|-|g')"
TARGET="$HOME/.claude/projects/-${ESCAPED}/memory"

mkdir -p "$TARGET"
cp -v "$REPO_DIR/.claude/memory/"*.md "$TARGET/"
echo ""
echo "Memory installed to: $TARGET"
echo "Claude Code will pick it up automatically in the next session."
