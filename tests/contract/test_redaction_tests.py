"""Coldline.

===================

File:              tests/contract/test_redaction_tests.py
Component:         Contract tests — The student's redaction tests
Purpose:           One assessed check per public Check-list row about the student's
                    tests/student/test_redaction.py and the worker's bindings: the static guard,
                    the worker's binding to the supplied redactor and guardrail (static, then
                    observed in-process), what the file's tests actually ran, and the two
                    supplied mutations.
Interacts With:    tests/student/test_redaction.py, src/worker/use_cases.py,
                    tests/security/student_guard.py, tests/security/worker_binding.py,
                    tests/security/guardrail_observation.py, tests/security/redaction_mutation.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Deterministic negative tests, mutation testing, evidence from executed runs
Tools:             Python 3.12, pytest

Assessed: a fresh starter has a template with no tests and a worker that imports no
redactor, so every row but the static guard fails until the worker and the two tests are
written. ``poe contract`` deselects them; ``poe redaction-tests-contract`` and ``poe
verify`` run them (through ``tests/security/assessed_run.py``, which requires every
registered case to have executed and passed), after the student tests as written. The
rows that run the student file are marked ``runtime``: the carried audit tests beside it
need the issuer, and the file is run in a subprocess that imports the running
configuration. The static rows must pass before any row executes the file; the mutation
runner refuses a file the guard rejects, and the binding row imports the worker only after
its static rules passed, which is why this module imports nothing from ``src/`` at
collection.
"""

from __future__ import annotations

import pytest

from tests.security import redaction_mutation as mutation
from tests.security import student_guard, worker_binding
from tests.security.worker_binding import TASK_ROOT

pytestmark = pytest.mark.assessed


def _inventory() -> mutation.Inventory:
    """Run the student file once as written, or fail the row with why it could not run."""
    try:
        return mutation.collect_inventory()
    except mutation.MutationError as exc:
        pytest.fail(str(exc))


def _verdict(name: str) -> mutation.Verdict:
    """Run one mutation against the student file, or fail the row with why it could not run."""
    try:
        return mutation.check(name)
    except mutation.MutationError as exc:
        pytest.fail(str(exc))


def test_student_file_uses_only_the_harness_and_asserts_each_outcome() -> None:
    """The student file imports only the harness, inspects nothing, and asserts what it owes.

    Static, over the file's bytes, never an import, and the precondition of every row
    below that executes it: the only imports are `pytest`, the annotations future,
    `typing` names and `InteractionHarness`; no name reads the environment, the
    filesystem, or a module's internals; `pytest` is used only for fixtures, the two
    permitted marks, `param` and `raises`; no function takes a pytest built-in fixture as
    a parameter; every test asserts over a value obtained from the supplied pipeline
    helper or the supplied redactor; and no name that is a Python builtin is bound
    anywhere in the file (`AssertionError` is what the mutations recognise a failing
    assertion by). `poe student-guard` is the same check, run inside `poe verify` before
    anything executes the file.
    """
    findings: list[str] = []
    for path in student_guard.STUDENT_PATHS:
        try:
            found = student_guard.findings(TASK_ROOT / path)
        except student_guard.StudentGuardError as exc:
            pytest.fail(str(exc))
        findings.extend(f"{path.as_posix()}: {item}" for item in found)
    assert findings == [], "; ".join(findings)


def test_worker_binds_the_supplied_redactor_and_guardrail_and_rebinds_nothing() -> None:
    """The worker calls `redact` from `common.redactor` and `validate_summary` from the guardrail.

    Static first, over the bytes of `src/worker/use_cases.py`, never an import: one
    module-level `from common.redactor import redact` and one `from worker.guardrail
    import validate_summary`, no other import of either module, no definition, assignment
    or other rebinding of either name, every use of each name as the callee of a call,
    every `redact(...)` call directly inside `WorkerApplication.process` (not inside a
    lambda or a nested function there, where it would run later than it is written) and
    none after the `validate_summary(...)` call there (the answer is redacted before the
    guardrail checks it, never the validated summary); no import beyond the file's
    imports as supplied plus `from common.redactor import redact`, each name under its own
    name; and no import of `pytest`, `_pytest`, `sys`, `importlib`, `builtins`, `gc`,
    `inspect`, `ctypes`, `types`, `runpy`, `unittest` (`unittest.mock` included) or
    `mock`, no `exec`, `eval`, `compile`, `__import__`, `globals`, `locals`, `vars`, `dir`,
    `getattr`, `setattr` or `delattr`, no three-argument `type(...)`, no dunder attribute,
    and no frame access (`currentframe`, `_getframe`, `f_builtins`, `f_globals`,
    `f_locals`, `f_back`, `f_code`, `tb_frame`, `gi_frame`, `cr_frame`, `ag_frame`). Only
    then is the worker imported and run in-process, with no stack, once per supplied
    response with the
    emulator's answer captured and `validate_summary` stood in for by a spy: the spy must
    be called exactly once with that answer redacted as supplied (as returned only when
    the worker has no `redact` call after the provider call) and nothing else; and again
    with the spy answering an inverted verdict, after which the stored record must follow
    the verdict. This is what makes the two mutations below target the supplied redactor,
    and what a worker with a redactor or a parser of its own fails.
    """
    try:
        found = worker_binding.application_findings(TASK_ROOT)
    except worker_binding.WorkerBindingError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)

    # The static rules passed, so the worker spells no door to the runner; now observe it.
    from tests.security import guardrail_observation as observation

    try:
        problems = observation.check(TASK_ROOT)
    except observation.ObservationError as exc:
        pytest.fail(str(exc))
    assert problems == [], "; ".join(problems)


@pytest.mark.runtime
def test_redaction_file_has_an_expected_redaction_test_and_a_limitation_test() -> None:
    """The file executes an expected-redaction test and a limitation test.

    The file is run once as written with the harness recording what each test did. A
    case counts as the expected-redaction test when it ran the worker with the note
    `N-01` and with the `pii-echo` response (one case for both, or one case each); a case
    counts as the limitation test when it called `harness.redact(...)`, ran the worker not
    at all, and is named after a documented limitation id (`test_rl_<nn>_...`). What a
    test names in its source counts for nothing.
    """
    inventory = _inventory()
    problems = inventory.problems()
    assert problems == [], "; ".join(problems) + "\n\n" + inventory.describe()


@pytest.mark.runtime
def test_the_expected_redaction_test_fails_when_the_note_redaction_call_is_removed() -> None:
    """Every case that ran N-01 fails against a copy of the worker without the note redaction.

    The `note-redaction-removed` mutation replaces every `redact(...)` call before the
    provider call in `WorkerApplication.process` with its argument, so the note reaches
    the log line and the model request as written and a test that asserts the four
    locations are clean fails. A test that would pass either way is named.
    """
    verdict = _verdict("note-redaction-removed")
    assert verdict.ok, "; ".join(verdict.problems)


@pytest.mark.runtime
def test_the_expected_redaction_test_fails_when_the_answer_redaction_call_is_removed() -> None:
    """Every case that ran pii-echo fails against a copy of the worker without the answer redaction.

    The `answer-redaction-removed` mutation replaces every `redact(...)` call after the
    provider call in `WorkerApplication.process` with its argument, so the contact the
    `pii-echo` answer adds reaches the stored summary and the `outcome_stored` record, and
    a test that asserts the four locations are clean fails. A test that would pass either
    way is named.
    """
    verdict = _verdict("answer-redaction-removed")
    assert verdict.ok, "; ".join(verdict.problems)
