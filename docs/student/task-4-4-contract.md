# Task 4.4 — PII redaction contract

Apply the supplied PII redactor to the worker's handling note and model answer, and test one
of its documented limitations. You place two calls of the supplied `redact` in
`src/worker/use_cases.py`, record the one supplied note the redactor handles wrongly in
`submission.yaml` (the note, the kind of error, the documented limitation behind it), and write
two tests in `tests/student/test_redaction.py`: one expected-redaction test and one test that
pins the limitation. You write no redactor, no pattern of your own, and no new fixture; you
change no other file.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `src/worker/use_cases.py`, `submission.yaml`, and `tests/student/test_redaction.py` | Automated, in this repository |
| Nothing under the three permitted files or the checks' own files changed while `poe verify` ran | Automated: `poe verify` records a hash snapshot as its first step and checks it as its last |
| `tests/student/test_redaction.py` imports only `pytest`, the `annotations` future, the permitted `typing` names, and `InteractionHarness`; uses none of the listed environment names anywhere (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...) and takes neither `.format` nor `.format_map` from anything; uses `pytest` only for fixtures, the `asyncio` and `parametrize` marks, `param` and `raises`; gives no function a parameter named after a pytest built-in fixture; every test asserts over a value obtained from the supplied pipeline helper or the supplied redactor; and no name that is a Python builtin (`AssertionError`, `print`, `len`, `id`, ...) is defined, assigned, imported or otherwise bound anywhere in the file | Automated, static, over the file's bytes, never an import (`poe student-guard`, inside `poe verify` before anything executes the file, and the first step of `poe student-tests`); the checks refuse to run a file that fails it |
| `src/worker/use_cases.py` imports `redact` from `common.redactor` once, at module level, and `validate_summary` from `worker.guardrail` once, at module level; rebinds neither name nor module; uses each name only to call it; calls `redact` only directly inside `WorkerApplication.process` (not inside a lambda or a nested function there) and never after the `validate_summary` call there (the raw answer is redacted before the guardrail checks it; the validated summary is never redacted); imports nothing beyond the file's imports as supplied plus `from common.redactor import redact` (no other module, no other name from those modules, no relative or `*` import, no alias); and reaches nothing beyond application code (no `pytest`, `_pytest`, `sys`, `importlib`, `builtins`, `gc`, `inspect`, `ctypes`, `types`, `runpy`, `unittest` or `mock`; no `exec`, `eval`, `compile`, `__import__`, `globals`, `locals`, `vars`, `dir`, `getattr`, `setattr`, `delattr` or `__builtins__`; no `type(...)` with three arguments; no dunder attribute; no frame access: `currentframe`, `_getframe`, `f_builtins`, `f_globals`, `f_locals`, `f_back`, `f_code`, `tb_frame`, `gi_frame`, `cr_frame`, `ag_frame`). Run in-process once per supplied response, the worker hands `validate_summary` the provider's answer redacted as supplied (as returned only while the worker has no `redact` call after the provider call), once, as its only argument, and stores the outcome the verdict names | Automated: the static part over the file's bytes (`poe worker-binding`, also a step of `poe verify`), then, only when it passes, the worker run in this process with no stack; one assessed row of `poe redaction-tests-contract` |
| The `N-01` run ends `COMPLETED` and its stored summary is the one a worker that redacts as supplied stores | Automated, against the running stack (`poe verify`): one reading with the supplied note through the open intake, the record read through the database, the expected summary computed from the reading alone; a failing row names the run and the guidance, never either summary |
| None of `N-01`'s marked values is in the worker logs, the model request, the audit records, or the stored summary, and none is in any log message the worker emits, or anything it writes to standard output or standard error, while it processes `N-01`, whether or not the message names the exception | Automated, against the running stack (`poe verify`), reading the four locations exactly as `poe pii-scan` does; then the worker run once more in the checks' own process with `N-01`, its standard streams redirected, and every captured log message and both streams searched |
| The `pii-echo` run ends `COMPLETED` with the expected redacted summary, the contact the response adds is in none of the four locations, and it is in no log message the worker emits, or anything it writes to standard output or standard error, while it processes `N-01` with the `pii-echo` answer, whether or not the message names the exception | Automated, against the running stack (`poe verify`); then the worker run once more in the checks' own process with `N-01` and `pii-echo` together, its standard streams redirected, and every captured log message and both streams searched for the contact and for `N-01`'s values |
| The malformed and manipulated responses still end `NEEDS_REVIEW` with the output policy's fixed message, the guardrail's code, and none of the model's text | Automated, against the running stack (`poe verify`) |
| One read of each finished record still leaves the four worker events in order and one summary read, with the fields the event list permits, the values the checks captured independently, and the requests' trace ids; the model-response digest is of the answer to the request a correct worker sends | Automated, against the running stack (`poe verify`), reading the trail back through the API container as `poe audit-trail` does |
| The Task 2 access rule still protects `GET /api/v1/exceptions/{exception_id}` | Automated, against the running stack (`poe verify`) |
| `answers.limitation_note`, `answers.limitation_type`, and `answers.documented_limitation` each hold one of the allowed values, and the sheet is not a copy of the sample | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| Your limitation note, limitation type, and documented limitation | Protected automated check, after you submit on the platform; no check in this repository reads the correct values |
| Your redaction file runs the worker with the note `N-01` and with the `pii-echo` response, and has a limitation test that calls the redactor and is named after a documented limitation id; the expected-redaction test fails when the note redaction call is removed and when the answer redaction call is removed | Automated, by running your file with its actions recorded and again against two mutated copies of `src/` (`poe verify`) |
| What the baseline and post-change scans and the redaction report's entry in your pull request show, and what your limitation test says the risk is | Your instructor, at the Task 4 Instructor Review; you use the redaction evidence again at the Project Defense |

The inherited Project 3 checks (smoke, end-to-end workflow, queue, SLO, gate, and runbook
contracts) also run inside `poe verify`, over the supplied checkpoint, and pass as shipped.

## The supplied material

| Supplied | Where | Note |
|---|---|---|
| The redactor | `src/common/redactor.py` | `redact(text)` returns the text with every recognized phone number, email address and contact name replaced by `[REDACTED:phone]`, `[REDACTED:email]`, `[REDACTED:name]`; `redact(None)` is `None`; version `1.0.0`. Not student-editable |
| Its documentation | `docs/security/redactor.md` | The call form, the recognized forms, the placeholders, where the worker applies it, and the limitations with ids `RL-01` to `RL-07`. The ids are what `answers.documented_limitation` names |
| The supplied notes | `tests/fixtures/pii/notes.yaml` | Seven synthetic notes, `N-01` to `N-07`, each with the PII values its fixture marks (a note with none lists none); `poe scenario --note <id>` sends one, `poe redaction-report` prints them all. Exactly one is handled wrongly by the redactor. Not student-editable |
| The supplied responses | `src/adapters/model/deterministic.py`, `docs/fidelity/ModelProvider.md` | `valid` (the default), `malformed`, `manipulated`, and `pii-echo`, a schema-valid answer that adds a contact number no note and no request holds; its marked value is known to `poe pii-scan` |
| The model request record | `src/adapters/model/request_log.py`, `src/worker/model_request.py` | The emulator records the text of each request it receives under the exception id, inside the worker container; `poe model-request <exception_id>` prints it and `poe pii-scan` reads it as the model request |
| The carried Task 4.3 completion | `src/api/routes.py`, `tests/student/test_output_guardrail.py`, `tests/student/test_audit.py` | The summary-read event and the five Task 4.3 tests, as the reference completion left them; `poe student-tests` still runs the tests. Not student-editable |
| The guardrail, the output policy, the event list, the audit sink | `src/worker/guardrail.py`, `docs/security/output-policy.md`, `docs/security/audit-events.md`, `src/common/audit.py` | As in Task 4.3. The event list states that `model_responded` digests the answer as the provider returned it, before redaction |
| The settled Task 2 material | `config/auth.yaml`, `src/api/security/`, `tests/fixtures/tokens/`, `tests/student/test_exception_access.py` | The verifier settings, the access rule, the eight token fixtures, and the eight access tests. Not student-editable |
| The student-test harness | `tests/security/interaction.py` | `InteractionHarness`: `run_worker(response, note=...)` runs the worker in-process with the real redactor, guardrail, emulator and sink, and `worker_logs`, `model_request`, `audit_trail`, `audit_text`, `expected_summary`, `pii_findings`, `redact`, `note` and `marked_values` expose the run and the fixture; `tests/student/test_redaction.py` documents how to use it. When the assessed checks run your file, it records what each test did |
| The student-test guard | `tests/security/student_guard.py` | Reads the file as bytes, without running it, and applies six flat rules; `poe student-guard` |
| The worker-binding check | `tests/security/worker_binding.py`, `tests/security/guardrail_observation.py` | The first reads `src/worker/use_cases.py` as bytes and requires the one permitted import of each supplied name, no rebinding, every `redact` call directly inside `process`, and no spelled path to the test runner (`poe worker-binding`); the second, run only after the first passes, runs the worker in-process with the provider's answers captured and the guardrail stood in for |
| The mutations | `tests/security/redaction_mutation.py` | `note-redaction-removed` and `answer-redaction-removed` over `src/worker/use_cases.py`, applied to temporary copies of `src/` made beside the directories it reads (`schemas/`, `config/`); `poe redaction-mutation` |
| The scan and the report | `tests/security/pii_scan.py`, `tests/security/redaction_report.py`, `tests/security/pii.py` | `poe pii-scan <exception_id>` searches the four locations for the marked values of the run's note and response and prints what it found where; `poe redaction-report` prints every note's original text, redacted text and marked values, with no verdict |
| The assessed-module runner | `tests/security/assessed_run.py` | Runs each assessed module under pytest with a junit report and requires every registered case to have executed and passed; `poe redaction-contract` and `poe redaction-tests-contract` go through it |
| The integrity snapshot | `tests/security/integrity.py` | Hashes your three files and the checks' own files when `poe verify` starts and compares them when it ends; `poe integrity-record` and `poe integrity-check` |

## The three steps

### Step 1 — Redact the note and the model's answer where they enter the worker

Start the stack as `README.md` describes. Before any code change, run
`poe scenario --note N-01` and then `poe pii-scan <exception_id>` with the id it printed; keep
that output. In `WorkerApplication.process`, redact the handling note where the worker first
reads it from the job, before the log line that records the job and before the note goes into
the model request, and use the redacted note from then on. Redact the provider's raw answer
before you pass it to `validate_summary`. Run `poe start` again (the worker image carries your
file), then `poe scenario --note N-01` and `poe scenario --response pii-echo`, and scan each
new exception id.

### Step 2 — Find and classify the redactor's limitation

Run `poe redaction-report`. For every supplied note it prints the original text, the redacted
text and the values the fixture marks. Find the one note whose redacted text does not match
its marked values: a marked value that stayed visible is a `false_negative`; text that is not
marked but was replaced is a `false_positive`. Record the note's id, the type, and the id of
the entry in the limitations section of `docs/security/redactor.md` that describes this exact
pattern, in `submission.yaml`. `poe answers` checks the format; the protected check reports
the result after you submit on the platform.

### Step 3 — Test the expected redaction and the limitation

Complete the two marked places in `tests/student/test_redaction.py` as the file's docstring
describes: the expected-redaction test runs the worker with `note="N-01"` and with the
`pii-echo` response and asserts, for both, `COMPLETED` with `harness.expected_summary(...)`
and an empty `harness.pii_findings(...)`; the limitation test, named `test_rl_<nn>_...` after
the id you recorded, redacts the note you found and asserts the redactor's full output for
it, stating the limitation in its docstring as a risk that remains. Run `poe student-tests`,
then `poe redaction-mutation` to see the expected-redaction test fail under each mutation.

## Commands

```shell
poe scenario [--response <name>] [--note <id>]   # one reading through the stack with the chosen response and note
poe pii-scan <exception_id>                      # search the four locations for the run's marked values
poe redaction-report                             # every supplied note: original, redacted, marked values
poe model-request <exception_id>                 # the request text the emulator received, from the worker container
poe audit-trail <exception_id>                   # one exception's ordered audit records
poe student-guard                                # the student file: imports, names, and asserts, without running it
poe worker-binding                               # the worker's bindings and reach, without running it
poe integrity-record                             # hash your files and the checks' files; the first step of `poe verify`
poe integrity-check                              # compare the tree with that snapshot; the last step of `poe verify`
poe student-tests                                # the student-test guard, then every test under tests/student/
poe student-tests-run                            # the bare pytest run behind it; forwards arguments (-k <name>)
poe redaction-mutation                           # what your tests ran, then your tests against the two mutated copies of src/
poe redaction-contract                           # the assessed rows that read the running stack
poe redaction-tests-contract                     # the assessed rows about your worker's bindings and your tests
poe answers                                      # the answer sheet's format only
poe verify                                       # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe student-guard`, `poe worker-binding`, `poe redaction-report` and
`poe answers` are static; your redaction tests need no stack (the carried audit tests beside
them need the issuer); every other command above needs the running stack.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| The handling note is redacted before the worker logs it or sends it to the model provider | `test_note_n01_values_are_absent_from_every_location` (the worker logs and the model request are the two places only that call keeps clean), with `test_note_n01_run_completes_with_the_expected_redacted_summary` |
| The model's raw answer is redacted before `validate_summary` checks it | `test_pii_echo_run_completes_redacted_with_its_contact_in_no_location` (only that call keeps the contact out of the stored summary and the `outcome_stored` record), supported by `test_worker_binds_the_supplied_redactor_and_guardrail_and_rebinds_nothing` (the worker binds the supplied redactor and the supplied guardrail by their own imports, redacts nothing after the guardrail call, and hands every answer to the guardrail redacted as supplied; it is also what makes the two mutation rows below target the supplied redactor) |
| `poe pii-scan` finds none of the marked PII values from `N-01` or `pii-echo` in the worker logs, the model request, the audit records, or the stored summary | `test_note_n01_values_are_absent_from_every_location` and `test_pii_echo_run_completes_redacted_with_its_contact_in_no_location` (each also searches every log message and the standard output and error of one in-process run, with `N-01`, respectively `N-01` and `pii-echo` together, not only the lines that name the exception) |
| `answers.limitation_note`, `answers.limitation_type`, and `answers.documented_limitation` use the allowed values in `submission.yaml`, and `submission.yaml` passes the public answer-format check | `test_submission_answers_use_the_allowed_values`, and `poe answers` |
| Your limitation note, limitation type, and documented limitation pass the protected answer check | The protected check on the platform; no check in this repository reads the correct values |
| Both expected-redaction runs reach `COMPLETED` with the expected redacted summary | `test_note_n01_run_completes_with_the_expected_redacted_summary` and `test_pii_echo_run_completes_redacted_with_its_contact_in_no_location` |
| `tests/student/test_redaction.py` has one expected-redaction test and one limitation test that names the documented limitation | `test_student_file_uses_only_the_harness_and_asserts_each_outcome` first (static), then `test_redaction_file_has_an_expected_redaction_test_and_a_limitation_test` (your file run once with its actions recorded) |
| `poe student-tests` passes | `poe student-tests` inside `poe verify` |
| The expected-redaction test fails when the note redaction call is removed | `test_the_expected_redaction_test_fails_when_the_note_redaction_call_is_removed` (the `note-redaction-removed` mutation) |
| The expected-redaction test fails when the answer redaction call is removed | `test_the_expected_redaction_test_fails_when_the_answer_redaction_call_is_removed` (the `answer-redaction-removed` mutation) |
| The Task 2 access rule still protects `GET /api/v1/exceptions/{exception_id}` | `test_the_task_2_access_rule_still_protects_the_summary_route` |
| The malformed and manipulated responses still end in `NEEDS_REVIEW` | `test_bad_responses_still_end_needs_review[malformed]` and `[manipulated]` |
| `poe audit-trail` still shows every event in `docs/security/audit-events.md` for one interaction | `test_the_audit_trail_still_reconstructs_one_interaction[n01-valid]`, `[pii-echo]`, `[malformed]` and `[manipulated]` |
| The pull request modifies only `src/worker/use_cases.py`, `submission.yaml`, and `tests/student/test_redaction.py` | `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py`, and `poe submission` (the `tests/contract/submission_validation.py` module, which applies the same boundary) inside `poe verify` |

The rows that read the running stack live in `tests/contract/test_redaction_contract.py`
(`poe redaction-contract`); the rows about your worker's bindings and your tests live in
`tests/contract/test_redaction_tests.py` (`poe redaction-tests-contract`); the last row is
`test_submission_change_stays_within_the_permitted_diff` in
`tests/contract/test_authoring_contract.py`. They are marked `assessed`: `poe contract` leaves
them out, and `poe verify` runs them through `tests/security/assessed_run.py`, which requires
every registered case to have executed and passed (a skipped or missing case fails the step).
The rows that touch the stack or run your tests are also marked `runtime`. A fresh checkout
fails most of them, which is the exercise; `test_bad_responses_still_end_needs_review`,
`test_the_task_2_access_rule_still_protects_the_summary_route` and
`test_student_file_uses_only_the_harness_and_asserts_each_outcome` pass on it, because the
carried Task 4.3 and Task 4.2 completions are in place and the template has no tests to check
yet.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/security/live_record.py` | One reading per interaction, submitted through the open intake with the supplied note and the response selector, then the `exceptions` table polled inside the `postgres` container until the record is in a finished state, and the record's output fields read from the same table. Nothing is read through the route, so no read is added to a trail the rows count |
| `tests/security/pii.py` and `tests/security/pii_scan.py` | The marked values of a run: the supplied note whose text the stored reading holds exactly (`tests/fixtures/pii/notes.yaml`, `pii:` per note) and the contact the supplied response adds. The four locations: the worker container's log lines naming the exception (`docker compose logs worker`), the request text the emulator recorded (`python -m worker.model_request` inside the worker container), every audit record's `details` rendered as JSON (`poe audit-trail --json`), and the stored summary. Each marked value is searched as a substring in each location; a scan is clean when all four were read and none holds a value. A finding is reported by the value's label and its location (`worker logs: N-01 phone`), never by the value itself, so the scan's output and a failing row's message are not one more place the detail reaches (the redaction report prints the values on purpose, for the comparison Step 2 asks of you). A location whose evidence is not there (no log line names the exception, or no request record) is `unavailable`, never clean: `poe pii-scan` exits 2 and the assessed rows fail |
| `tests/security/interaction.py` | The in-process harness your file and the binding observation use: the worker run once per call with the real redactor, guardrail, emulator and sink, the planted procedure as the running stack retrieves it, the emulator's record of each request, the log lines captured, and the trail from the memory store. `expected_summary` replays the emulator over the request a correct worker sends (the note redacted), redacts the answer, and takes the guardrail's verdict, without reading the record. The `N-01` row and the `pii-echo` row also run the worker here once each (with `N-01`; with `N-01` and the `pii-echo` answer together), with `sys.stdout` and `sys.stderr` redirected for the run, and search every log message any logger emitted during the run and everything the run wrote to either stream for the marked values of that note and that response, whatever the message names, because the live scan reads only the lines that name the exception, neither a raw note nor a raw answer logged before its redaction carries the exception id, and a `print` of either is in no log at all. When the assessed checks run your file, each worker run (with its note), each request, and each call of `redact` is recorded against the pytest case that made it |
| `tests/security/trail.py` | One exception's audit records, as `poe audit-trail --json` prints them: the event sequence, each worker event's permitted and required fields as scalars, the values the checks captured independently (the reading id, the provider, the digest and length of the raw answer the emulator gives the request a correct worker sends, the guardrail's decision over that answer, the state and summary the database holds), the read's subject and role, and every record's trace id |
| `tests/security/student_guard.py` | The student file read as bytes (UTF-8 only), parsed, never imported. Six flat rules: the four permitted import forms; the forbidden names in every position (the harness's own handles included), and `format` and `format_map` taken as attributes from anything; the permitted uses of `pytest`; no reserved parameter name; the assertion each test owes, over a value from the pipeline helper or the redactor, with provenance tracked per parameter and per call into helpers and nested functions; and no binding of a Python builtin name in any position (a class, a function, a target, a parameter, an import, a handler, a capture: `AssertionError` is what the mutations recognise a failing assertion by) |
| `tests/security/worker_binding.py` | `src/worker/use_cases.py` read as bytes, parsed, never imported: one module-level `from common.redactor import redact` and one `from worker.guardrail import validate_summary`, no other import of either module; no definition, assignment, parameter, handler, capture or attribute that rebinds either name; every use of each name as the callee of a call; every `redact(...)` call directly inside `WorkerApplication.process`, not inside a lambda or a nested function there, and none after the `validate_summary(...)` call there (one inside its argument list is before it); a call's side of the provider call read by one classifier shared with the mutations (after the provider call ends is the answer side, anything else the note side, a call on the provider call's own line included); none of the names that rebind a module at runtime; the reach rules (no runner module imported in any form or reached through another module, `unittest.mock` and `mock` among them, no dynamic name, `getattr`, `vars`, `locals` and `dir` among them, no three-argument `type(...)`, no dunder attribute, no frame access by `currentframe`, `_getframe`, `f_builtins`, `f_globals`, `f_locals`, `f_back`, `f_code`, `tb_frame`, `gi_frame`, `cr_frame` or `ag_frame`); and the import allowlist (exactly the file's imports as supplied plus `from common.redactor import redact`, each name under its own name). The rules are syntactic; with the allowlist no module beyond the supplied ones can be imported and no dynamic attribute access can be spelled, and a patch that reaches the runner only through the objects the harness hands in, with plain attribute access, is the recorded residual |
| `tests/security/guardrail_observation.py` | Only after the binding check passed: the worker imported and run in this process, with no stack, once per supplied response, with the emulator wrapped so its raw answer is captured and `validate_summary` replaced for the run by a spy. The spy must be called once, handed that answer redacted as supplied (as returned is accepted only for a worker whose source has no `redact` call after the provider call), and nothing else; then each response is run again with the spy answering an inverted verdict, after which the record must follow it |
| `tests/security/redaction_mutation.py` | First the student-test guard must pass, or nothing runs. Then the file is run once as written with its actions recorded: a case counts for `N-01` when it ran the worker with that note, for `pii-echo` when it ran the worker with that response, and as the limitation test when it called `harness.redact` without running the worker under a name carrying a documented limitation id. Then one rerun per mutation against a copy of `src/` made beside the directories it reads at runtime: `note-redaction-removed` replaces every `redact(...)` call on the note side of the provider call in `process` with its argument (every `N-01` case must fail); `answer-redaction-removed` does the same on the answer side (every `pii-echo` case must fail); the side is the one the binding check's classifier gives. A worker without a call on one side is already that mutation's shape; the copy runs unchanged and the required cases must fail on it as they stand. Only an assertion failure counts; a case that still passes or is skipped is named, and an error or a non-assertion exception makes that rerun invalid |
| `tests/security/assessed_run.py` | Each assessed module run under pytest with a junit report, then, outside that process, the report compared with the registered inventory of the module's cases: every registered case must appear once and have passed |
| `tests/security/integrity.py` | SHA-256 digests of the three student files and every file under `tests/contract/`, `tests/security/`, `src/api/security/`, `src/common/`, `src/adapters/model/`, `schemas/`, `docs/security/`, `tests/fixtures/`, plus `src/api/routes.py`, `src/worker/guardrail.py`, the answer schema, the carried `config/auth.yaml` and the three carried student test files, `infra/corpus/documents.jsonl`, and `pyproject.toml`, recorded to a file outside the repository when `poe verify` starts and compared when it ends |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) and `test_submission_change_stays_within_the_permitted_diff` | `submission.yaml` is one plain YAML mapping whose `answers` holds the three fields, each one of its allowed values and none blank, and is not a copy of `submission-sample.yaml`; the diff from the merge base with `main` touches only the three permitted files |

The runs of your file leave your files untouched: each mutation copies `src/` to a temporary
directory, changes the copy, runs your file against it, and deletes the copy; the recording of
your tests' actions goes to a temporary file the checks read and delete.

## Student-editable paths

- `src/worker/use_cases.py` (the two redaction calls in `WorkerApplication.process`; the
  guardrail call, the audit events and the rest stay as carried from Task 4.3)
- `submission.yaml`
- `tests/student/test_redaction.py`

That is the whole list. The redactor (`src/common/redactor.py`), its documentation
(`docs/security/redactor.md`), the fixtures (`tests/fixtures/pii/notes.yaml`), the supplied
responses (`src/adapters/model/`), the carried Task 4.3 files (`src/api/routes.py`,
`tests/student/test_output_guardrail.py`, `tests/student/test_audit.py`), the settled Task 2
material, the supplied tests, `compose.yaml`, and the workflows stay as supplied. Before you
push, run `git status` and `git diff --stat`: if anything else changed, the public check
reports the boundary violation rather than your work.
