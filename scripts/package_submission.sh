#!/usr/bin/env bash
# Build the code-freeze zip: <teamid>_<psid>.zip, holding exactly what git tracks at HEAD.
# Ignored files (.venv, node_modules, data/, .env, secrets) are never included, because git does not track them.
#   scripts/package_submission.sh TEAMID PSID [--no-video]
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 TEAMID PSID [--no-video]" >&2
  exit 2
fi
team=$1 psid=$2 no_video=${3:-}
name="${team}_${psid}"
cd "$(git rev-parse --show-toplevel)"

if [ -n "$(git status --porcelain)" ]; then
  echo "uncommitted changes: commit (and push) first, so the zip matches GitHub" >&2
  git status --short >&2
  exit 1
fi

exclude=()
if [ "$no_video" = "--no-video" ]; then
  exclude=(":(exclude)docs/*.mp4")
fi

git archive --format=zip --prefix="${name}/" -o "${name}.zip" HEAD -- . "${exclude[@]}"

echo "wrote ${name}.zip from $(git rev-parse --short HEAD) ($(du -h "${name}.zip" | cut -f1), $(unzip -Z1 "${name}.zip" | grep -vc '/$') files)"
for p in node_modules .venv .env data/ deploy/secrets; do
  if unzip -Z1 "${name}.zip" | grep -q "^${name}/${p}"; then
    echo "ERROR: ${p} is inside the zip" >&2
    exit 1
  fi
done
echo "checked: no node_modules, .venv, .env, data/ or deploy/secrets inside"
