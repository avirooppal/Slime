#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN="${PYTHON_BIN:-python3}"
SELFHEAL_CMD=("$PYTHON_BIN" -m selfheal)

TRIAL_DIR="$(mktemp -d)"
CFG="$TRIAL_DIR/config.yaml"
DB="$TRIAL_DIR/trial.db"
export DOCKER_CONFIG="$TRIAL_DIR/docker_cfg"
mkdir -p "$DOCKER_CONFIG"
printf '{"auths":{}}\n' > "$DOCKER_CONFIG/config.json"

cleanup() {
    rm -rf "$TRIAL_DIR"
}
trap cleanup EXIT

echo "=== 1. Starting disposable Docker Compose demo stack ==="
docker compose up -d
for i in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:18080/ >/dev/null 2>&1 && curl -fsS http://127.0.0.1:18081/ >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "=== 2. Running selfheal init ==="
"${SELFHEAL_CMD[@]}" init --config "$CFG" --scan-dir "$REPO_ROOT/docs/demo"

"$PYTHON_BIN" - "$CFG" "$DB" <<'PY'
import sys
from pathlib import Path
import yaml

cfg_path = Path(sys.argv[1])
db_path = Path(sys.argv[2])
data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
assert data["dry_run"] is True, "init must write dry_run: true"
assert data["safety"]["enabled_actions"] == [], "init must leave enabled_actions empty"
data["database"] = str(db_path)
data["metrics_enabled"] = False
data["learning_period"] = True
data["stability_seconds"] = 2
data["safety"]["verification_interval_seconds"] = 1
data["safety"]["verification_timeout_seconds"] = 15
data["services"] = [s for s in data["services"] if s["name"] in ("nginx", "web", "worker")]
cfg_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
PY

echo "=== 3. Running selfheal doctor ==="
"${SELFHEAL_CMD[@]}" doctor --config "$CFG"

echo "=== 4. Running selfheal run --once (dry-run baseline) ==="
"${SELFHEAL_CMD[@]}" run --config "$CFG" --once

echo "=== 5. Injecting chaos in dry-run and running one dry-run detection cycle ==="
"${SELFHEAL_CMD[@]}" chaos --docker-demo --config "$CFG" --output "$TRIAL_DIR/chaos_dry.jsonl" --scratch "$TRIAL_DIR/scratch_dry"

echo "=== 6. Showing incidents after dry-run chaos ==="
"${SELFHEAL_CMD[@]}" incidents --config "$CFG"

echo "=== 7. Enabling restart_container and running real repair with verification ==="
"${SELFHEAL_CMD[@]}" enable-action restart_container --config "$CFG"
docker kill slime-demo-worker-1 >/dev/null
"${SELFHEAL_CMD[@]}" run --config "$CFG" --no-dry-run --once

echo "=== 8. Verifying container recovery and resolved incident postmortem ==="
STATUS="$(docker inspect -f '{{.State.Status}}' slime-demo-worker-1)"
if [ "$STATUS" != "running" ]; then
    echo "ERROR: expected slime-demo-worker-1 to be running after repair, got $STATUS" >&2
    exit 1
fi
curl -fsS http://127.0.0.1:18081/ >/dev/null
"$PYTHON_BIN" - "$DB" <<'PY'
import sys
from selfheal.storage.store import Store

store = Store(sys.argv[1])
incidents = store.incidents()
resolved = [i for i in incidents if i.state.value == "resolved"]
assert resolved, f"expected at least one resolved incident after repair, got {[i.state.value for i in incidents]}"
pm = store.postmortem(resolved[-1].id)
assert pm is not None and "Stable" in pm["markdown"], "expected verified Stable postmortem"
store.close()
PY
"${SELFHEAL_CMD[@]}" incidents --config "$CFG"
echo "=== Linux trial completed: real restart_container repair and verification succeeded ==="
