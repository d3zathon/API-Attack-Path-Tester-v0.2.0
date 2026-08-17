# API Attack-Path & Authorization Tester (APIAT)

APIAT is a CLI-first offensive-security tool for **authorized API assessments**. It accepts an OpenAPI specification plus multiple test identities, exercises authorization boundaries, verifies suspicious behavior, correlates confirmed findings into attack paths, and produces evidence-based reports.

It is intentionally **not** a generic vulnerability scanner and **not** an autonomous AI pentesting agent.

## What APIAT tests

- **BOLA / IDOR** — controlled object-identifier substitution with baseline comparison.
- **Broken function-level authorization (BFLA)** — role-aware differential testing of operations.
- **Privilege escalation** — focused testing of privileged operation namespaces under lower roles.
- **Parameter tampering** — controlled changes to security- and workflow-sensitive fields.
- **Business-logic/workflow flaws** — targeted checks for state-sensitive operations without an observable prerequisite.
- **Verification** — findings are promoted only when the check has a meaningful behavioral signal; raw anomalies are not treated as proof.
- **Attack paths** — confirmed findings are correlated into concise multi-step hypotheses.

## Why v0.2 is easier to use

The old prototype used `aapt`, which collides with Android's Asset Packaging Tool on Kali/Linux. v0.2 uses the unambiguous command **`apiat`**.

It also adds:

- one-command demo: `apiat demo`
- lab lifecycle: `apiat lab start|stop|status`
- automatic report-directory creation
- friendly input and target errors instead of raw tracebacks for normal CLI mistakes
- Linux installer with pipx/venv fallback
- Windows PowerShell installer
- backward-compatible `aapt` alias for early v0.1 users
- cleaner CLI defaults for reports

## Fastest setup on Kali/Linux

From the repository root:

```bash
./scripts/install.sh
```

If `pipx` is installed, APIAT is installed with pipx. Otherwise the script creates `.venv`, installs the project, and links `apiat` into `~/.local/bin`.

Then run the complete local demo:

```bash
apiat demo
```

That command:

1. builds and starts the deliberately vulnerable local API
2. waits for `/openapi.json` to become ready
3. scans it with the bundled OpenAPI/roles/seed files
4. writes JSON and HTML reports
5. prints the verified findings and attack-path count

Reports are written to `reports/demo.json` and `reports/demo.html`.

## Manual workflow

Start the local vulnerable lab:

```bash
apiat lab start
```

Then scan it:

```bash
apiat scan examples/lab-openapi.yaml --base-url http://127.0.0.1:8000 --roles examples/roles.yaml --seed examples/seed.yaml --report reports/lab.json --html reports/lab.html
```

Check or stop the lab:

```bash
apiat lab status
apiat lab stop
```

## Real-world authorized testing

For an authorized assessment, provide your OpenAPI contract, approved test identities, and the in-scope base URL:

```bash
apiat scan openapi.yaml --base-url https://api.example.test --roles roles.yaml --report reports/assessment.json --html reports/assessment.html
```

Use only credentials and targets explicitly approved for testing. `--insecure` disables TLS certificate verification and should be reserved for controlled lab environments.

## Roles file

A role file describes the identities APIAT is allowed to use:

```yaml
roles:
  - name: customer
    headers:
      Authorization: "Bearer CUSTOMER_TEST_TOKEN"
  - name: manager
    headers:
      Authorization: "Bearer MANAGER_TEST_TOKEN"
  - name: admin
    headers:
      Authorization: "Bearer ADMIN_TEST_TOKEN"
```

For real assessments, never commit live credentials. Use short-lived test tokens and environment/secret management appropriate to the engagement.

## Architecture

```text
OpenAPI contract
      |
      v
endpoint model -----> role-aware HTTP executor
      |                         |
      +----------+--------------+
                 v
             focused checks
                 |
                 v
             verification
                 |
                 v
              findings
                 |
                 v
          attack-path correlation
                 |
          +------+------+
          v             v
       JSON            HTML
```

The code is separated into `core`, `checks`, `models`, `reporting`, and `cli` packages so security checks can evolve independently from transport and presentation.

## Developer setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest
```

For Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -e ".[test]"
pytest
```

## Docker

The local lab is containerized. APIAT itself does not require Docker when testing an external authorized API. Docker is only needed for the bundled lab/demo.

The lab intentionally contains authorization/workflow weaknesses and should not be exposed to an untrusted network.

## Portfolio talking points

This project demonstrates API-security methodology rather than a pile of payloads: OpenAPI contract parsing, identity-aware test orchestration, differential verification, evidence preservation, attack-path correlation, containerized lab design, CLI engineering, and automated tests.

The next substantial engineering upgrades should be a stateful workflow DSL, tenant-aware object inventories, stronger semantic response comparison, OAuth/OIDC session handling, and safer mutation controls for production-like APIs.

## Versioning

Current release: **0.2.0**

Primary command: `apiat`

Compatibility alias: `aapt`
