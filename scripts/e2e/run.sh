#!/usr/bin/env bash
# End-to-end test of a MaskGuard release in isolated containers, on a database that is not the demo.
#
#   scripts/e2e/run.sh dist/maskguard-X.Y.Z-py3-none-any.whl     # test a built wheel
#   scripts/e2e/run.sh pypi                                      # test what `pip install maskguard` gets
#
# Starts a fresh PostgreSQL 16 container and a fresh python:3.12 container, then runs scripts/e2e/inner.sh inside the
# second one: create a clinic database, install MaskGuard, run it in production mode on a read-only account, and
# check scanning, review, masking per role, bypass attempts, refusals, the integrity proof, the HTTPS API and
# restarts. Every step prints PASS or FAIL; the script exits non-zero on the first failure. Both containers are
# removed at the end. Host networking is used only so the app container can reach PyPI through a proxy if needed;
# nothing else on the host is used.
set -euo pipefail
cd "$(dirname "$0")/../.."
PKG="${1:?usage: run.sh <wheel>|pypi}"
PORT="${MG_E2E_PG_PORT:-55432}"
DB=mg-e2e-db; APP=mg-e2e-app
SUPER_PW="$(openssl rand -hex 16)"
cleanup() { docker rm -f "$DB" "$APP" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$DB" --network host -e POSTGRES_PASSWORD="$SUPER_PW" postgres:16 -p "$PORT" >/dev/null
for _ in $(seq 1 60); do docker exec "$DB" pg_isready -q -p "$PORT" && break; sleep 1; done

mounts=(-v "$PWD/scripts/e2e:/e2e:ro")
if [ "$PKG" != pypi ]; then mounts+=(-v "$(realpath "$PKG"):/pkg/$(basename "$PKG"):ro"); PKG="/pkg/$(basename "$PKG")"; fi
ca=(); [ -f /root/.ccr/ca-bundle.crt ] && ca=(-v /root/.ccr/ca-bundle.crt:/ca.crt:ro -e PIP_CERT=/ca.crt)

docker run --name "$APP" --network host "${mounts[@]}" "${ca[@]}" \
  -e HTTPS_PROXY -e HTTP_PROXY -e https_proxy -e http_proxy -e NO_PROXY=127.0.0.1,localhost -e no_proxy=127.0.0.1,localhost \
  -e PKG="$PKG" -e PGPORT="$PORT" -e SUPER_PW="$SUPER_PW" python:3.12 bash /e2e/inner.sh
