"""Read demo health, or stop only the exact process recorded by this playground."""
import json
import sqlite3
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import psutil
import yaml

root = Path(__file__).resolve().parent
config = yaml.safe_load((root / ".slime/config.yaml").read_text(encoding="utf-8"))
if sys.argv[1:] == ["stop"]:
    database = root / ".slime/slime.db"
    if not database.exists():
        print("Nothing has been started yet.")
        raise SystemExit(0)
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_processes'"
        ).fetchone()
        row = db.execute(
            "SELECT pid,create_time FROM managed_processes WHERE service='playground'"
        ).fetchone() if exists else None
    if row:
        try:
            process = psutil.Process(row[0])
            if process.create_time() != row[1]:
                raise SystemExit("PID identity changed; refusing to stop an unrelated process.")
            process.terminate()
            process.wait(timeout=5)
            print("Stopped the playground app.")
        except psutil.NoSuchProcess:
            print("Playground app is already stopped.")
    else:
        print("No playground-owned process recorded.")
elif not sys.argv[1:]:
    url = config["services"][0]["http_url"]
    print("Health endpoint: " + url)
    try:
        with urlopen(url, timeout=3) as response:
            print(json.dumps(json.load(response), indent=2))
    except URLError:
        print("OFFLINE - the demo app is not responding.")
else:
    raise SystemExit("Usage: python check.py [stop]")
