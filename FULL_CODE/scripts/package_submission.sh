#!/usr/bin/env bash
# Build the code-freeze zip the way the TalentAP coding guidelines (v1.1, page 2) describe: commit everything, take a
# fresh `git clone` (it keeps .git and leaves out .env and every ignored file), name the folder TEAMID_PSID and zip it.
#   FULL_CODE/scripts/package_submission.sh TEAMID PSID [--shallow]  -> TEAMID_PSID.zip next to the repository folder
# --shallow clones only the latest commit: still a git clone with .git, but about 27 MB instead of about 100 MB.
# Checks before writing: no uncommitted changes; only README.md, .gitignore, LICENSE and FULL_CODE/ at the top (plus the
# hidden .git and .github); no secrets, data, databases, virtual environments or node_modules inside.
set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ] || { [ $# -eq 3 ] && [ "$3" != "--shallow" ]; }; then
  echo "usage: $0 TEAMID PSID [--shallow]" >&2
  exit 2
fi
name="${1}_${2}"
depth=()
[ "${3:-}" = "--shallow" ] && depth=(--depth 1)
repo="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
out="$(dirname "$repo")/${name}.zip"

if [ -n "$(git -C "$repo" status --porcelain)" ]; then
  echo "uncommitted changes: commit (and push) first, so the zip matches GitHub" >&2
  git -C "$repo" status --short >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone --quiet --no-hardlinks ${depth[@]+"${depth[@]}"} "file://$repo" "$work/$name"
git -C "$work/$name" remote remove origin   # the clone points at a local path; drop it rather than ship it

top=$(cd "$work/$name" && ls -A | grep -vxE '\.git|\.github|README\.md|\.gitignore|LICENSE|FULL_CODE' || true)
if [ -n "$top" ]; then
  echo "ERROR: only README.md, .gitignore, LICENSE and FULL_CODE/ may sit at the top; found:" >&2
  echo "$top" >&2
  exit 1
fi
bad=$(cd "$work/$name" && find . -path ./.git -prune -o \( -name .env -o -name node_modules -o -name .venv -o -name venv \
  -o -name __pycache__ -o -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' -o -name '*.pkl' -o -path ./FULL_CODE/data \
  -o -name '*.zip' -o -name production.env \) -print)
if [ -n "$bad" ]; then
  echo "ERROR: these must not be in the zip:" >&2
  echo "$bad" >&2
  exit 1
fi

rm -f "$out"
(cd "$work" && zip -qr "$out" "$name")
unzip -tq "$out" > /dev/null
echo "wrote $out from $(git -C "$repo" rev-parse --short HEAD): $(du -h "$out" | cut -f1), $(unzip -Z1 "$out" | grep -vc '/$') files"
echo "checked: layout README.md + .gitignore + LICENSE + FULL_CODE/; no .env, data/, databases, venvs, node_modules"
