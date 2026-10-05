"""Coldline.

===================

File:              tests/student/test_redaction.py
Component:         Student tests — PII redaction
Purpose:           Your two redaction tests: no marked PII from N-01 or pii-echo reaches any
                    location, and the redactor's behavior on the limitation note is pinned.
Interacts With:    tests/security/interaction.py, src/worker/use_cases.py, src/common/redactor.py,
                    docs/security/redactor.md, tests/fixtures/pii/notes.yaml,
                    src/adapters/model/deterministic.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic negative tests, redaction before the first copy, a limitation
                    recorded on purpose
Tools:             Python 3.12, pytest

This file is yours: it is one of the three files this Task permits you to change.
`poe student-tests` runs it, and `poe verify` runs it as written and again against two
supplied mutations of the worker (the note redaction call removed; the answer redaction
call removed), so the expected-redaction test must be able to fail.

The `harness` fixture below runs the real worker in this process, with the real redactor,
guardrail, model emulator (no latency) and audit sink over a memory store, the supplied
procedure the running stack retrieves for the scenario's reading, the emulator's record of
each request it received, and the worker's log lines captured:

- `record = await harness.run_worker(response, note=note_id)` creates one fresh exception
  for the scenario's reading, with the supplied note `note_id` (`"N-01"`) as its handling
  note when given, processes it once with the named emulator response (`"valid"`,
  `"malformed"`, `"manipulated"`, `"pii-echo"`), and returns the stored record: assert
  `record.state` (compare it with the state name, `record.state == "COMPLETED"`) and
  `record.summary`.
- `harness.expected_summary(record.exception_id)` is the summary a worker that redacts
  as supplied stores for that run, computed from the reading alone.
- `harness.pii_findings(record.exception_id, note="N-01")` and
  `harness.pii_findings(record.exception_id, response="pii-echo")` search the run's four
  locations (the worker logs, the model request, the audit records, the stored summary)
  for the values the fixture marks for that note, or the contact the response adds, and
  return one line per value found; an empty list is a clean scan. The four locations are
  also yours one by one: `harness.worker_logs(id)`, `harness.model_request(id)`,
  `harness.audit_trail(id)` (records with `.event` and `.details`) and
  `harness.audit_text(id)` (the trail as text).
- `harness.redact(text)` is the supplied redactor, exactly as the worker calls it, and
  `harness.note("N-03")` is a supplied note's text, so the limitation test need not paste
  the note. `harness.marked_values(note="N-01")` returns the values the fixture marks.

These tests need no running stack: nothing here reads the API. The assessed checks run
this file and record what each test did; that record, not a test's name, is how they tell
the two tests apart. The expected-redaction test is the one that ran the worker with the
note `N-01` and with the `pii-echo` response (one test for both, or two tests one each);
the limitation test is the one that called `harness.redact(...)`, ran the worker not at
all, and is named after the documented limitation id, `test_rl_<nn>_...`.

Before anything runs this file, `poe student-guard` reads it (without running it) and
applies six flat rules, which `poe verify`, `poe student-tests` and the assessed checks
enforce the same way. Each rule is checked by presence, with no exceptions for how a name
came to be bound, so a rejected line is fixed by removing or renaming what it names:

- the only imports are `import pytest`, `from __future__ import annotations`,
  `from typing import <name>` for `Any`, `Annotated`, `Literal`, `Optional`, `Union`,
  `cast`, `TYPE_CHECKING` or `Final`, and
  `from tests.security.interaction import InteractionHarness` (no `from pytest import ...`,
  no other `typing` name, and no `as` except on one of those typing names);
- these names are not used anywhere, not even as your own variables: `__file__`,
  `__import__`, `__builtins__`, `importlib`, `inspect`, `sys`, `os`, `subprocess`,
  `builtins`, `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr`, `eval`, `exec`,
  `compile`, `open`, `Path`, plus a few more that reach the same places (the guard's message
  names the one it found), no `x.__anything__`, no `.format` or `.format_map` taken from
  anything (f-strings are fine), and no harness internal such as `x.repository` or
  `x.root` (the methods above are all a test needs);
- `pytest` appears only as `@pytest.fixture`, `pytest.mark.asyncio`,
  `pytest.mark.parametrize`, `pytest.param`, and `pytest.raises`;
- no function in this file, whether a test, a fixture, a helper, or a function nested in a
  test, has a parameter named `request`, `monkeypatch`, `pytestconfig`, `capsys`, `capfd`,
  `caplog`, `tmp_path`, `tmp_path_factory`, or `recwarn`: pytest fills those with fixtures
  that reach the environment, so rename such a parameter, for example to `resp`;
- every test asserts over a value it obtained from the harness: the record from
  `harness.run_worker(...)`, the lines from `harness.pii_findings(...)`, the text from
  `harness.worker_logs(...)`, `harness.model_request(...)` or `harness.audit_text(...)`,
  the records from `harness.audit_trail(...)`, the summary from
  `harness.expected_summary(...)`, or the output of `harness.redact(...)`, itself or in a
  helper defined in this file that it hands the value;
- no name that is a Python builtin (`AssertionError`, `print`, `len`, `id`, `type`, ...)
  is defined, assigned, imported or otherwise bound anywhere in this file, as a class, a
  function, a variable, a parameter, a loop or `with` target or an alias: the checks
  recognise a failing assertion by that exception's name, and a rebound builtin changes
  what an assertion or a call means.

Tests that describe the run and the redactor's output, as the two marked places below
ask, meet all six.
"""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API, with their own memory store and audit sink."""
    return InteractionHarness()


# --- Test 1 of 2: the expected redaction.
# Run the worker with `note="N-01"` and run it with the "pii-echo" response. For both runs,
# assert that the record's state is COMPLETED and its summary equals
# `harness.expected_summary(record.exception_id)`, and that
# `harness.pii_findings(record.exception_id, note="N-01")` (respectively
# `response="pii-echo"`) is empty: none of the marked values is in the worker logs, the
# model request, the audit records, or the stored summary.


# --- Test 2 of 2: the limitation.
# Name the test after the documented limitation id you recorded in submission.yaml
# (`test_rl_<nn>_...`), and state the limitation in its docstring as a risk that remains.
# Redact the note you found in Step 2 (`harness.redact(harness.note("N-..."))`) and assert
# the redactor's actual output for it, the full redacted text, so a change in what the
# redactor produces fails this test and tells the next engineer to look at the
# documentation again. Do not run the worker in this test.
