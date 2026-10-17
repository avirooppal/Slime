# Local recovery playground

From the repository root, activate the installed Slime environment, then:

```sh
cd examples/playground
python setup.py
selfheal run --config .slime/config.yaml --once
selfheal enable-action restart_managed_process --config .slime/config.yaml
selfheal run --config .slime/config.yaml --no-dry-run --once
python check.py
selfheal incidents --config .slime/config.yaml
python check.py stop
```

The first agent run is dry-run. The second starts the disposable loopback HTTP
service and checks five seconds of health. The health helper prints the URL,
PID and uptime. Only a recorded process with the same PID birth time is stopped.

For continuous operation omit `--once`; press Ctrl+C before stopping the child.
Repeated immediate failures can trigger cooldown/flapping protection.
`setup.py` preserves existing configuration and never starts the service itself.

For a fresh experiment, copy `app.py`, `setup.py`, and `check.py` into a new
empty directory and run `python setup.py` there using the same installed Python
environment. Do not copy `.slime/`; it contains absolute launch paths and old
ownership state. Stop the previous service first. Each experiment gets a new
configuration, database and dynamically selected loopback port.

This is an application demo, not a package build script: `setup.py` only prepares
the local agent configuration. Run `python setup.py` directly.
