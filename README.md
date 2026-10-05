# Coldline Task 4.4 — PII redaction

This repository starts from the Task 3 checkpoint, with the settled token verification and
access rule from Task 2 and the settled output guardrail and audit events from Task 3, and
adds a PII redactor at a fixed version with its documentation in `docs/security/redactor.md`.
A free-text handling note travels with each reading, and some notes name a contact person
or give a phone number or email address. At this checkpoint the worker logs the note as it
reads the job, places it unchanged in the text sent to the model provider, and the model can
repeat it in the summary it writes, which the worker stores and records in the audit trail.
The redactor replaces the kinds of PII it recognizes with a labeled placeholder;
synthetic handling notes in `tests/fixtures/pii/notes.yaml` cover each kind, and one more
supplied model response, `pii-echo`, returns a summary that adds a synthetic contact detail
that appears in neither the note nor the rest of the model request. You apply the redactor
at the two points in the worker where the note and the model's answer enter, find and
classify the one supplied note the redactor handles wrongly, and test both the expected
redaction and the limitation.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-4/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS) the settled `config/auth.yaml` names |
| Jaeger | `http://localhost:16686` | Open traces; the trace ids the audit records carry are these |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS | `http://localhost:4566` | Inspect the emulated object-storage and queue endpoint |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. If you remap the issuer port,
keep `config/auth.yaml` unchanged: it is supplied in this Task and names the default port.
Host-side tools (the in-process test harness and `poe token-check`) resolve the issuer's
origin from `COLDLINE_ISSUER_HOST_PORT` (the environment, then `.env`, then the default), and
the API uses the Compose-network origin.

This Task runs as its own Compose project, `coldline-task-4-4`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

### After you edit a file

The worker image carries `src/worker/use_cases.py` as it was when it was built. After editing
it, run `poe start` again: it rebuilds the images and recreates the containers, which is what
the Task page means by "restart the stack as `README.md` describes". `poe restart` restarts the
existing containers **without rebuilding** and is not enough. Your tests under `tests/student/`
run the worker in-process from your checkout and need no rebuild; the carried Task 3 audit
tests beside yours need the running issuer.

## Command path

For this Task, run the supplied commands in this order:

```text
poe start
poe ingest
poe scenario --note N-01                 # before any code change: keep this scan
poe pii-scan <exception_id>
poe scenario --note N-01                 # after Step 1 (and `poe start` again)
poe pii-scan <exception_id>
poe scenario --response pii-echo         # after Step 1
poe pii-scan <exception_id>
poe redaction-report                     # Step 2
poe answers
poe student-tests                        # Step 3
poe redaction-mutation
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe scenario [--response valid\|malformed\|manipulated\|pii-echo] [--note N-01..N-07]` | Send the supplied reading with a fresh identity, the chosen emulator response and, with `--note`, one of the supplied handling notes in place of the reading's own; wait for a finished state; print the exception id, the state, and the trace ids. The two options combine. `valid` and the reading's own note are the defaults |
| `poe pii-scan <exception_id>` | Search four places for the marked PII values of that exception's note and response, and print what it found where, naming each value by its label (`N-01 phone`) and never printing the value itself, so the scan's output is not one more place the detail reaches: the worker logs (the worker container's lines naming the exception), the model request (the text the emulator received, from its record in the worker container), the audit records (every record's `details`), and the stored summary. The marked values are the ones `tests/fixtures/pii/notes.yaml` lists for the supplied note the run carried and the contact the `pii-echo` response adds; a run with the reading's own note has no note values to search, and the scan says so. Exits 1 when any marked value is found, 0 when every location was read and none holds one, and 2 when a location could not be read or its evidence is not there: no worker log line names the exception, or the request record is gone (both happen when the worker container is recreated after the run); that location is printed `unavailable`, never `clean`, so scan a fresh `poe scenario` run |
| `poe redaction-report` | Print, for every supplied note, the original text, the redactor's output, and the values the fixture marks. It names no note as right or wrong: comparing them is Step 2. Needs no stack |
| `poe model-request <exception_id>` | Print the text of the model request the emulator received for one exception, from the worker container's request records |
| `poe audit-trail <exception_id>` | Print every audit record of one exception, oldest first, with its event, the exception id, the trace id of the request that recorded it, the time, and its fields. Runs inside the API container |
| `poe student-guard` | Read `tests/student/test_redaction.py` without running it and apply six flat rules: only `import pytest`, the `annotations` future, the permitted `typing` names (`Any`, `Annotated`, `Literal`, `Optional`, `Union`, `cast`, `TYPE_CHECKING`, `Final`), and `InteractionHarness` may be imported; none of the listed environment names (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...) appears anywhere, and neither `.format` nor `.format_map` is taken from anything; `pytest` is used only for fixtures, the `asyncio` and `parametrize` marks, `param` and `raises`; no function has a parameter named after a pytest built-in fixture (`request`, `monkeypatch`, `tmp_path`, ...: rename it, for example to `resp`); every test asserts over a value obtained from the supplied pipeline helper or the supplied redactor; and no name that is a Python builtin (`AssertionError`, `print`, `len`, `id`, ...) is defined, assigned, imported or otherwise bound anywhere in the file (the mutations recognise a failing assertion by that exception's name). Runs inside `poe verify` before anything executes the file and as the first step of `poe student-tests`; the assessed checks refuse to run a file it rejects |
| `poe worker-binding` | Read `src/worker/use_cases.py` without running it and check that it imports `redact` from `common.redactor` and `validate_summary` from `worker.guardrail` once each, at module level, rebinds neither name nor module, uses each name only to call it, calls `redact` only directly inside `WorkerApplication.process` (not inside a lambda or a nested function there, whose call would run later than it is written) and never after the `validate_summary` call there (the raw answer is redacted before the guardrail checks it, never the validated summary), imports nothing beyond what the file imported when you received it plus `from common.redactor import redact` (no other module, no other name from those modules, no alias: the lesson's change needs no import but that one), and reaches nothing beyond application code (no test-runner or interpreter module, `unittest.mock` included, no `exec`, `eval`, `compile`, `__import__`, `globals`, `locals`, `vars`, `dir`, `getattr`, `setattr` or `delattr`, no three-argument `type(...)`, no dunder attribute, no frame access such as `currentframe`, `_getframe`, `f_builtins`, `f_globals`, `f_locals` or `tb_frame`). This is the static half of one assessed check about your worker; its other half, run only when this passes, runs the worker in-process with no stack and checks that every answer reaches `validate_summary` redacted as supplied (as returned only while the worker has no `redact` call after the provider call) and that the stored outcome follows the guardrail's verdict |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash your three files and the checks' own files into a snapshot outside the repository, then compare the tree with it, so a file that changed while the run was in progress is named |
| `poe student-tests` | Run the student-test guard, then every test under `tests/student/`: your `test_redaction.py`, the carried Task 3 guardrail and audit tests, and the settled Task 2 access tests; a file the guard rejects is named and never collected. `poe student-tests-run` is the bare pytest run behind it and forwards arguments (`poe student-tests-run -k <name>`), as `poe e2e-tests` does for `poe e2e` |
| `poe redaction-mutation` | Run your file once as written, recording which note and response each test ran the worker with and which tests called the redactor, then rerun it against two copies of `src/` with one thing changed each (the `redact` calls before the provider call removed; the `redact` calls after it removed) and report which of your tests still pass |
| `poe redaction-contract` | The assessed checks that read the running stack: the `N-01` and `pii-echo` runs' state, stored summary and four locations, the refused answers, the audit trail, and the inherited Task 2 access rule. Runs the module through `tests/security/assessed_run.py`, which requires every registered check to have executed and passed |
| `poe redaction-tests-contract` | The assessed checks about your worker's bindings and your tests: the guard, the worker's binding to the supplied redactor and guardrail (static, then observed in-process), what your tests ran, and the two mutations (only an assertion failure counts as a detection), through the same runner |
| `poe token-check <fixture>`, `poe auth-checks`, `poe auth-config` | Task 2's diagnosis tools over the settled `config/auth.yaml` and the access rule, kept |
| `poe answers` | The answer sheet's format only: the three answers are present, each one of its allowed values, and the sheet is not a copy of `submission-sample.yaml` |
| `poe submission` | The same check plus the permitted-files boundary: the diff from your merge base touches only the three permitted files |
| `poe verify` | The public student verification path: it starts the stack, exercises the inherited platform, and runs this Task's own checks |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract` | Project 3's own checks, inherited and passing as shipped; `poe verify` runs them |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe smoke` | Check the initialized running platform, including the issuer's documents |
| `poe e2e` | Run the external API-to-worker workflow, including the joined trace |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` records an integrity snapshot of your three files and the checks' own files, runs
the student-test guard and the worker-binding check before anything executes your file or
imports your worker, then the unit tests; it starts the stack, ingests the supplied corpus, runs
the smoke tests, then this Task's assessed checks against the running stack (the `N-01` run
`COMPLETED` with the expected redacted summary and none of its marked values in the four
locations, the `pii-echo` run `COMPLETED` with the expected redacted summary and its contact in
no location, each of these two also run once in the checks' own process with every log message
and everything written to the standard streams searched, the two refused answers still
`NEEDS_REVIEW`, the audit trail of each interaction
in order with the fields and trace ids the event list requires, the inherited access rule),
then the end-to-end exception workflow, the inherited queue, SLO, gate, and runbook checks,
your student tests (behind the guard again), the assessed checks about your worker's bindings
and your tests (the guard, the binding and the in-process observation, what each test ran, and
the two mutations), the answer-sheet format check, the permitted-files boundary, and finally
the integrity check against the snapshot. Each assessed step requires every one of its
registered checks to have executed and passed. The Project 3 exercise commands
(`poe inject-failure`, `poe redrive`, `poe trigger-alert-load`, `poe verify-alert-recovery`,
`poe dev-failure-lab`) still run but are not part of this Task.

## Folder map

```text
repository root/
├── config/              Retrieval configuration, settled since Sprint 2, and the settled auth.yaml
├── docs/                Student guidance, public contracts, fidelity notes, and the security material
│   ├── contracts/       Machine-readable public contracts, including this Task's answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter, including the emulator's responses and request record
│   ├── security/        The supplied workflow, threat catalog, control matrix, access policy, output policy, audit events, and the redactor's documentation
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, the settled threat model, and the supplied Project 3 runbook
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus (one procedure carries the planted instruction), query set, and investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions, including the output fields and the audit table
├── schemas/             The supplied output schema the guardrail enforces
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition, the audit-trail command
│   │   └── security/    The settled TokenVerifier and require_access rule; not student-editable
│   ├── worker/          Background application code, the procedure lookup, the supplied guardrail, the request-record reader, the dead-letter depth poller
│   ├── common/          The supplied audit sink and the supplied redactor both services may use; not student-editable
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the model emulator, its responses and its request log, the audit store, the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks, including the redactor's, the emulator's, and the mutation tooling's
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, and this Task's assessed redaction checks
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── fixtures/        Supplied fixtures: the token fixtures, the credential values, and the supplied handling notes under pii/
    ├── security/        Supplied tooling: the in-process harness, the student guard, the binding check, the mutations, the scan, the report
    ├── student/         Your test_redaction.py beside the carried Task 3 tests and the settled Task 2 access tests
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 4 lesson (Task 4.4 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-4-contract.md`](docs/student/task-4-4-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, and the
   three permitted paths.
3. [`docs/security/redactor.md`](docs/security/redactor.md) — the redactor's version, call form,
   recognized kinds, placeholders, and the limitations its authors know about.
4. [`tests/fixtures/pii/notes.yaml`](tests/fixtures/pii/notes.yaml) — the supplied handling
   notes with the PII values each one is marked to contain.
5. [`docs/security/audit-events.md`](docs/security/audit-events.md) — the events one interaction
   leaves, in order, and what Task 4 changes in them.
6. [`src/common/redactor.py`](src/common/redactor.py) — the supplied redactor, with the call
   form in its docstring.
7. [`tests/student/test_redaction.py`](tests/student/test_redaction.py) — the template you
   complete, with the harness documented in its docstring.
8. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the settled Task 1 threat
   model this Project's controls answer; TH-07 is the threat this Task closes with C-05.

The application source lives in six flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, token verification and the access rule, configuration, composition, and the audit-trail command |
| `worker` | Background processing, retries, procedure lookup, the output guardrail, the request-record reader, the dead-letter depth poller, configuration, and composition |
| `common` | The audit sink and the redactor the API and the worker share, and the event names |
| `domain` | Provider-neutral contracts, state rules, identity, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL (exception records and audit records), pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, the deterministic model emulator with its supplied responses and request log, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`; the token
verification settings live in `config/auth.yaml`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; it returns the provider's raw answer text, which the worker redacts and the guardrail checks |
| `Retriever` | Look up relevant context or documents; the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; no adapter is composed yet |

## Test levels

| Level | Requires Compose | Main question |
|---|---|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Does no marked PII reach any location, does the limitation stay as documented, and do the carried Task 3 and Task 2 tests still hold? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe verify`,
`poe runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your three files, the running stack and the audit table,
and are expected to fail on a fresh checkout; `poe contract` skips them too, and
`poe redaction-contract`, `poe redaction-tests-contract` and `poe verify` run them. Your
redaction tests run the worker in-process from `src/` and need no stack; the carried audit tests
beside them read the in-process API with the `dispatcher-valid` token, whose verifier fetches
the key set from the configured `jwks_url`, so they need the issuer running.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast. The protected
answer check compares your limitation note, limitation type and documented limitation with the
expected values after you submit on the platform; no file in this repository holds those
values. Follow the Task lesson's instructor-review and progression policy.

## Task boundary

Task 4.4 asks you to place the two redaction calls in `src/worker/use_cases.py`, record the
three answers in `submission.yaml`, write the two tests in `tests/student/test_redaction.py`,
run `poe verify`, open a pull request that changes only those three files, and add the baseline
`N-01` scan, the post-change `N-01` scan, the post-change `pii-echo` scan, and the redaction
report's entry for the limitation note to the pull request description, with each command and
when you ran it.

The only student-editable paths are:

- `src/worker/use_cases.py`
- `submission.yaml`
- `tests/student/test_redaction.py`

Keep the redactor (`src/common/redactor.py`), its documentation (`docs/security/redactor.md`),
the supplied notes (`tests/fixtures/pii/notes.yaml`), the emulator and its supplied responses
and request log (`src/adapters/model/`), the guardrail, the schema, the output policy and the
event list, the audit sink, the carried Task 3 files (`src/api/routes.py`,
`tests/student/test_output_guardrail.py`, `tests/student/test_audit.py`), the settled Task 2
material (`config/auth.yaml`, `src/api/security/`, the token fixtures, the access tests), the
credential values under `tests/fixtures/credentials/`, the supplied tests, and
`.github/workflows/task.yml` exactly as supplied; the public check compares the diff from your
merge base against the three permitted files and reports any other change as a boundary
violation. In `src/worker/use_cases.py`, the guardrail call and the audit events from Task 3
stay as they are; your change is the two redaction calls.

### Student walkthrough

See **Task 4: PII redaction** in your course platform for the full walkthrough. In outline:
start the stack, run the `N-01` scenario and scan it before changing any code and keep that
scan, redact the note where the worker reads it and the answer before the guardrail, run
`poe start` again and scan the `N-01` and `pii-echo` runs, run the redaction report and record
the limitation note, its type and its documented limitation, write the two tests, prove the
expected-redaction test can fail with `poe redaction-mutation`, run `poe verify`, open and merge
your pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. The token issuer is a development service: it publishes one
fixed key set over plain HTTP and issues no tokens; the eight fixtures were signed once and
committed. The Compose PostgreSQL password, the LocalStack access keys, and the worker's
model-provider key are development values. These values are listed once more in
`tests/fixtures/credentials/test-values.yaml` so the audit checks can search for them. Never
place real credentials, personal data, or production records in this repository. Every handling
note in this repository is synthetic: the phone numbers are fictional 555-01xx numbers, the
email addresses use reserved example domains, and every person named is invented. Test with the
supplied readings and notes only.

The redactor recognizes three kinds of personal detail in the forms `docs/security/redactor.md`
states, and nothing else; its limitations are listed there. A clean `poe pii-scan` shows that
the values the fixtures mark are absent from the four places it searches for that run, and only
when all four were read: a location whose evidence is gone is reported `unavailable`, not clean.
It does not show that every note is free of personal data, and it is not evidence of compliance
with a privacy regulation such as HIPAA. The stored reading and the queued job keep the raw
note; that is a residual risk this Task does not close.

The model emulator's four responses are a property of this emulator and of nothing else: the
guardrail bounds what any answer can store, and nothing here claims to detect or prevent
prompt injection. The emulator's record of each request it receives is tooling for this Task's
checks, not a claim about how a hosted provider stores what it is sent. See
[ModelProvider fidelity](docs/fidelity/ModelProvider.md).

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. Stopping and starting one Compose container is a local fault
control, not an ECS service event. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`; the audit table is in the PostgreSQL volume. LocalStack object and queue
contents are deliberately not persisted; the initializer re-uploads the supplied corpus
artifacts and re-provisions the queue on every start. The worker's request records live inside
the worker container and are gone when it is recreated. The `poe reset` command deletes the
named volumes. This topology makes no backup, replication, high-availability, disaster-recovery,
capacity, latency-SLO, or availability claim beyond what Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
