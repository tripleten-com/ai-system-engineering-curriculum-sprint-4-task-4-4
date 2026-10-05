"""Coldline.

===================

File:              tests/security/redaction_mutation.py
Component:         Security tooling — Redaction mutations
Purpose:           Record what the student's redaction tests actually do, then rerun them against
                    copies of the worker with the redaction calls on one side removed.
Interacts With:    tests/student/test_redaction.py, tests/security/interaction.py,
                    tests/security/trace.py, tests/security/student_guard.py,
                    tests/security/worker_binding.py, tests/security/pii.py,
                    src/worker/use_cases.py, docs/security/redactor.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Mutation testing, tests that can fail, evidence from executed runs, complete
                    workspaces, only assertion failures as evidence
Tools:             Python 3.12, ast, pytest (as a subprocess)

A test proves something only if it can fail. This module first runs the student file once
as written, with the harness recording every action each test takes
(``tests/security/trace.py``): that run is the **inventory** of executed cases, one per
collected pytest case. The file owes two kinds of case:

- an **expected-redaction case** ran the worker with the supplied note ``N-01``
  (``harness.run_worker(..., note="N-01")``) and ran the worker with the ``pii-echo``
  response; one case may do both, or two cases one each;
- a **limitation case** called ``harness.redact(...)``, ran the worker not at all, and is
  named after a documented limitation id (``test_rl_<nn>_...``, an id from
  ``docs/security/redactor.md``).

A name in the source, a constant, or a comment counts for nothing; only what a test did
does. Then it copies ``src/`` to a temporary directory, beside every top-level directory
the copied code reads relative to itself at runtime (``schemas/``, ``config/``), changes one
thing in the copy, runs the file against it (``PYTHONPATH`` puts the copy first), and judges
the junit outcomes. The two supplied mutations, each over ``WorkerApplication.process``:

- ``note-redaction-removed``: every ``redact(...)`` call before the provider call is replaced
  by its argument; every case that ran the worker with ``N-01`` must fail.
- ``answer-redaction-removed``: every ``redact(...)`` call after the provider call is replaced
  by its argument; every case that ran the worker with ``pii-echo`` must fail.

The provider call is ``self._provider.summarize(...)``; a ``redact`` call's side is its
position in ``process`` relative to it, decided by the one classifier the binding check
and this module share (``worker_binding.call_side``: a call that starts after the provider
call ends is on the answer side, any other call is on the note side, a call on the
provider call's own line included), which is why the binding check requires every
``redact`` call to sit inside ``process``, directly and not inside a lambda or a nested
function. A worker with no ``redact`` call on one side is
already that mutation's shape, so the copy is left unchanged and the run proceeds: the
required cases must fail on it as they stand, which they do when they assert what the
lesson asks (the copy stores the note or the contact unredacted).

Only an assertion failure counts as evidence. A case that ``passed`` or was ``skipped``
did not notice the change; a case that ``errored`` never reached its assertion and makes
the run invalid, which is reported by name; and a failure whose exception is anything but
``AssertionError`` (read from the junit failure's ``type`` or ``message``: a missing file,
a module that cannot be imported, an ``AttributeError`` or ``TypeError`` raised inside the
mutated copy, a ``pytest.raises`` that did not raise) is an invalid run too, never a
detection. pytest's exit code is kept and validated: an interrupted (a collection error
included), internal, or usage failure is a tooling error, not a verdict. Cases are keyed
by their full pytest node id on both sides.

Before any of these runs, the student file passes ``tests/security/student_guard.py``. A
file the guard rejects is never executed here: ``MutationError`` names the findings instead.
Source files are read as UTF-8 with an optional BOM (``utf-8-sig``) and the copy is written
back without one. The mutations are applied to the temporary copies only; the student's
files are never changed.

``python -m tests.security.redaction_mutation`` (``poe redaction-mutation``) prints the
inventory and the outcome of both mutations; ``tests/contract/test_redaction_tests.py``
asserts the same verdicts, one per Check-list row.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from tests.security import pii, student_guard, trace, worker_binding

TASK_ROOT = Path(__file__).resolve().parents[2]
STUDENT_TEST = Path("tests/student/test_redaction.py")
USE_CASES = Path("src/worker/use_cases.py")
REDACT_CALL = "redact"
PROVIDER_CALL = "summarize"
FIRST_NOTE = pii.FIRST_NOTE
ECHO_RESPONSE = "pii-echo"
MUTATIONS: tuple[str, ...] = ("note-redaction-removed", "answer-redaction-removed")
PYTEST_TIMEOUT_SECONDS = 300
# pytest's exit codes that are verdicts: 0 all passed, 1 some failed, 5 nothing collected.
# 2 (interrupted, a collection error included), 3 (internal error), and 4 (usage error) are
# not: the run did not happen as asked.
PYTEST_VERDICT_EXITS = frozenset({0, 1, 5})
# The directory the mutated copy of `src/` is made from, and the directories the copied
# code reads relative to its own location at runtime (`Path(__file__).resolve().parents[2]
# / "<directory>/..."`): the guardrail's schema, the composition root's auth settings.
# Every such directory is copied beside the mutated `src/`, so the copy never raises an
# infrastructure exception for a file the real tree has. `runtime_directories` reads the
# list from the source itself; these two are the ones the shipped tree names.
SOURCE_DIRECTORY = "src"
KNOWN_RUNTIME_DIRECTORIES: frozenset[str] = frozenset({"schemas", "config"})
_RUNTIME_DIRECTORY = re.compile(
    r"Path\(__file__\)\.resolve\(\)\.parents\[2\]\s*/\s*[\"']([A-Za-z0-9_.-]+)[/\"']"
)
# The one exception a failing case may have raised to count as evidence: pytest's rewritten
# `assert`, or an `AssertionError` raised outright. Every other exception is an invalid run.
ASSERTION_EXCEPTION = "AssertionError"
_EXCEPTION_MESSAGE = re.compile(r"^([A-Za-z_][\w.]*)(?::|$)")
_EXCEPTION_LOCATION = re.compile(r":\d+:\s+([A-Za-z_][\w.]*)\s*$")
# A documented limitation id in a test's name: `test_rl_nn_...`, `test_RL-nn_...`.
_LIMITATION_NAME = re.compile(r"(?i)rl[_-]?(\d{2})")
Side = worker_binding.Side


class MutationError(RuntimeError):
    """Report that a mutation could not be applied or run, as opposed to a test verdict."""


# --- The transform -------------------------------------------------------------------------


def _is_redact_call(node: ast.AST) -> bool:
    """Return whether a node is a call spelled ``redact(...)``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == REDACT_CALL
    )


def _argument(call: ast.Call) -> ast.expr | None:
    """Return the text a ``redact(...)`` call was handed: its first argument, or ``text=``."""
    if call.args:
        return call.args[0]
    for keyword in call.keywords:
        if keyword.arg == "text":
            return keyword.value
    return None


class _RemoveRedaction(ast.NodeTransformer):
    """Replace every ``redact(...)`` call on one side of the provider call by its argument."""

    def __init__(self, side: Side, provider: ast.Call) -> None:
        """Remember which side to strip and the provider call the sides are read against."""
        self.side = side
        self.provider = provider
        self.removed = 0

    def visit_Call(self, node: ast.Call) -> ast.AST:
        """Strip a redaction call on the chosen side; leave every other call alone."""
        self.generic_visit(node)
        if not _is_redact_call(node):
            return node
        if worker_binding.call_side(node, self.provider) != self.side:
            return node
        argument = _argument(node)
        if argument is None:
            return node
        self.removed += 1
        return ast.copy_location(argument, node)


def remove_redaction(source: str, side: Side) -> tuple[str, int]:
    """Replace the ``redact(...)`` calls on one side of the provider call by their arguments.

    ``side`` is ``"note"`` (the calls on the note side of ``self._provider.summarize(...)``
    in ``WorkerApplication.process``) or ``"answer"`` (the calls on the answer side), as
    ``worker_binding.call_side`` reads them. Returns the mutated source and how many calls
    were replaced; zero means the worker has no redaction call on that side, and the
    source comes back unchanged. A worker without ``WorkerApplication.process`` or without
    a provider call in it has lost the supplied shape, and that is a tooling error, not a
    verdict.
    """
    tree = ast.parse(source)
    process = worker_binding.process_method(tree)
    if process is None:
        raise MutationError(
            f"{USE_CASES.as_posix()} defines no `WorkerApplication.process`; the mutations "
            "need the supplied worker's shape"
        )
    provider = worker_binding.provider_call(process)
    if provider is None:
        raise MutationError(
            f"`WorkerApplication.process` in {USE_CASES.as_posix()} makes no provider call "
            f"(`{PROVIDER_CALL}(...)`); the mutations need the supplied worker's shape"
        )
    transformer = _RemoveRedaction(side, provider)
    transformer.visit(process)
    if transformer.removed == 0:
        return source, 0
    return ast.unparse(ast.fix_missing_locations(tree)), transformer.removed


@dataclass(frozen=True)
class Mutation:
    """One mutation: the side it strips, the cases it judges, and how it is described."""

    name: str
    side: Side
    judged: str


MUTATION_TABLE: dict[str, Mutation] = {
    "note-redaction-removed": Mutation(
        name="note-redaction-removed",
        side="note",
        judged=f"cases that ran the worker with the note {FIRST_NOTE!r}",
    ),
    "answer-redaction-removed": Mutation(
        name="answer-redaction-removed",
        side="answer",
        judged=f"cases that ran the worker with the {ECHO_RESPONSE!r} response",
    ),
}


def apply_mutation(name: str, source_root: Path) -> int:
    """Rewrite the worker under the temporary ``src`` copy; return how many calls were removed."""
    mutation = MUTATION_TABLE.get(name)
    if mutation is None:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    path = source_root / "worker/use_cases.py"
    # `utf-8-sig` drops a leading BOM, which `ast.parse` rejects in an already-decoded
    # string; the copy is written back without one.
    mutated, count = remove_redaction(path.read_text(encoding="utf-8-sig"), mutation.side)
    path.write_text(mutated, encoding="utf-8")
    return count


# --- The inventory: what each collected test actually did ----------------------------------


@dataclass(frozen=True)
class ExecutedCase:
    """Describe one collected pytest case by what it did through the harness.

    ``name`` is the case's full node id, the identity the trace and the junit report share;
    ``responses`` and ``notes`` are the emulator responses and supplied notes it ran the
    worker with; ``redactions`` counts its calls of ``harness.redact``.
    """

    name: str
    responses: frozenset[str]
    notes: frozenset[str]
    redactions: int
    outcome: str
    actions: tuple[str, ...] = ()

    @property
    def ran_worker(self) -> bool:
        """Return whether the case ran the worker at all."""
        return bool(self.responses)

    @property
    def ran_first_note(self) -> bool:
        """Return whether the case ran the worker with the supplied note N-01."""
        return FIRST_NOTE in self.notes

    @property
    def ran_echo(self) -> bool:
        """Return whether the case ran the worker with the pii-echo response."""
        return ECHO_RESPONSE in self.responses

    @property
    def limitation_id(self) -> str | None:
        """Return the limitation id the case's function name carries (`RL-nn`), if any."""
        function = self.name.rsplit("::", 1)[-1].split("[", 1)[0]
        match = _LIMITATION_NAME.search(function)
        return f"RL-{match.group(1)}" if match else None


@dataclass(frozen=True)
class Inventory:
    """Hold the executed cases of one run of the student file as written."""

    student_file: Path
    cases: dict[str, ExecutedCase]
    documented_limitations: tuple[str, ...]

    @classmethod
    def from_run(
        cls,
        student_file: Path,
        outcomes: dict[str, str],
        events: list[dict[str, object]],
        documented_limitations: tuple[str, ...],
    ) -> Inventory:
        """Join junit outcomes with the harness's recorded actions, per full case id."""
        responses: dict[str, set[str]] = {name: set() for name in outcomes}
        notes: dict[str, set[str]] = {name: set() for name in outcomes}
        redactions: dict[str, int] = dict.fromkeys(outcomes, 0)
        actions: dict[str, list[str]] = {name: [] for name in outcomes}
        for event in events:
            case = event.get("case")
            if not isinstance(case, str) or case not in outcomes:
                continue
            kind = event.get("kind")
            if kind == "worker":
                response = event.get("response")
                note = event.get("note")
                if isinstance(response, str):
                    responses[case].add(response)
                if isinstance(note, str):
                    notes[case].add(note)
                described = f"ran the worker with {response!r}"
                if isinstance(note, str):
                    described += f" and the note {note!r}"
                actions[case].append(described)
            elif kind == "redact":
                redactions[case] += 1
                actions[case].append("called redact")
        return cls(
            student_file,
            {
                name: ExecutedCase(
                    name,
                    frozenset(responses[name]),
                    frozenset(notes[name]),
                    redactions[name],
                    outcome,
                    tuple(actions[name]),
                )
                for name, outcome in outcomes.items()
            },
            documented_limitations,
        )

    @property
    def note_cases(self) -> set[str]:
        """Return the cases that ran the worker with N-01: what note-redaction-removed judges."""
        return {name for name, case in self.cases.items() if case.ran_first_note}

    @property
    def echo_cases(self) -> set[str]:
        """Return the cases that ran pii-echo: what answer-redaction-removed judges."""
        return {name for name, case in self.cases.items() if case.ran_echo}

    @property
    def limitation_cases(self) -> set[str]:
        """Return the cases that called the redactor, ran no worker, and name a documented id."""
        return {
            name
            for name, case in self.cases.items()
            if case.redactions > 0
            and not case.ran_worker
            and case.limitation_id in self.documented_limitations
        }

    def problems(self) -> list[str]:
        """Return everything this file lacks for its required executed cases."""
        if not self.cases:
            return [
                f"{self.student_file.as_posix()} ran no test; write the tests the template marks"
            ]
        problems: list[str] = []
        if not self.note_cases:
            problems.append(
                f"no test ran the worker with the note {FIRST_NOTE!r} "
                f'(`harness.run_worker(..., note="{FIRST_NOTE}")`): the expected-redaction '
                "test runs it and asserts what reached the four locations"
            )
        if not self.echo_cases:
            problems.append(
                f"no test ran the worker with the {ECHO_RESPONSE!r} response "
                f'(`harness.run_worker("{ECHO_RESPONSE}")`): the expected-redaction test runs '
                "it and asserts what reached the four locations"
            )
        candidates = {
            name for name, case in self.cases.items() if case.redactions > 0 and not case.ran_worker
        }
        if not candidates:
            problems.append(
                "no test called `harness.redact(...)` without running the worker: write the "
                "limitation test, which redacts the note you found and asserts the redactor's "
                "actual output for it"
            )
        elif not self.limitation_cases:
            documented = ", ".join(self.documented_limitations)
            names = ", ".join(sorted(candidates))
            problems.append(
                "the limitation test must be named after the documented limitation id "
                f"(`test_rl_<nn>_...`, one of {documented}); found {names}"
            )
        return problems

    def describe(self) -> str:
        """Render the inventory as a Markdown table, for `poe redaction-mutation` and messages."""
        lines = ["| Case | Did | Outcome |", "|---|---|---|"]
        for name in sorted(self.cases):
            case = self.cases[name]
            did = "; ".join(case.actions) or "-"
            lines.append(f"| `{name}` | {did} | {case.outcome} |")
        return "\n".join(lines)


@dataclass(frozen=True)
class RunResult:
    """What one run of the student file reported, per junit test case.

    ``changed`` is how many redaction calls the mutation removed in the copy; zero means
    the worker had none on that side and the copy ran unchanged.
    """

    mutation: str
    outcomes: dict[str, str]
    returncode: int = 1
    changed: int = 0


@dataclass(frozen=True)
class Verdict:
    """Whether one mutation made the required cases fail, and why not."""

    mutation: str
    required: set[str]
    problems: list[str] = field(default_factory=list)
    changed: int = 0

    @property
    def ok(self) -> bool:
        """Return whether the mutation is proven by the student's tests."""
        return not self.problems


# --- Running the student file ----------------------------------------------------------------


def failure_exception(failure: ET.Element) -> str:
    """Return the name of the exception a junit failure reports, or ``""`` when it says none.

    Read in this order: the element's ``type`` attribute when a writer sets one; the
    ``message`` attribute, which pytest fills with the exception line (``<Name>: <text>``,
    or the bare ``assert ...`` line for a rewritten assertion, whose ``AssertionError: ``
    prefix pytest strips); and the last line of the failure text, which pytest's long
    traceback ends with ``<path>:<line>: <Name>``. A dotted name is reduced to its last
    component.
    """
    declared = failure.attrib.get("type", "").strip()
    if declared:
        return declared.rsplit(".", 1)[-1]
    message = failure.attrib.get("message", "").strip()
    if message.startswith("assert") and (len(message) == 6 or not message[6].isalnum()):
        return ASSERTION_EXCEPTION
    matched = _EXCEPTION_MESSAGE.match(message)
    if matched:
        return matched.group(1).rsplit(".", 1)[-1]
    text = (failure.text or "").strip()
    if text:
        located = _EXCEPTION_LOCATION.search(text.splitlines()[-1])
        if located:
            return located.group(1).rsplit(".", 1)[-1]
    return ""


def _parse_junit(report: Path) -> dict[str, str]:
    """Return each junit test case's outcome, keyed by its full case id.

    The key is ``trace.junit_case_id(classname, name)``, the same identity the trace
    records. Two test cases with one identity make the report unusable, so the run is
    rejected. A failure is ``failed`` only when its exception is ``AssertionError``; any
    other exception, or one the report does not name, is recorded as an ``error`` with
    the exception's name after a colon (``error:AttributeError``, ``error:unknown``).
    """
    outcomes: dict[str, str] = {}
    if not report.is_file():
        return outcomes
    for case in ET.parse(report).iter("testcase"):
        identity = trace.junit_case_id(
            case.attrib.get("classname", ""), case.attrib.get("name", "")
        )
        if identity in outcomes:
            raise MutationError(
                f"the junit report names {identity} twice; one outcome per collected case is "
                "required"
            )
        failure = case.find("failure")
        if case.find("error") is not None:
            outcomes[identity] = "error"
        elif failure is not None:
            exception = failure_exception(failure)
            if exception == ASSERTION_EXCEPTION:
                outcomes[identity] = "failed"
            else:
                outcomes[identity] = f"error:{exception or 'unknown'}"
        elif case.find("skipped") is not None:
            outcomes[identity] = "skipped"
        else:
            outcomes[identity] = "passed"
    return outcomes


def runtime_directories(root: Path = TASK_ROOT) -> set[str]:
    """Return the top-level directories the code under ``src/`` reads relative to itself."""
    found: set[str] = set()
    for path in sorted((root / SOURCE_DIRECTORY).rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for match in _RUNTIME_DIRECTORY.finditer(path.read_text(encoding="utf-8-sig")):
            found.add(match.group(1))
    return found


def build_workspace(root: Path, workspace: Path) -> Path:
    """Copy ``src/`` and every runtime directory under ``workspace``; return the copied ``src``."""
    ignored = shutil.ignore_patterns("__pycache__", "*.pyc")
    source_root = workspace / SOURCE_DIRECTORY
    shutil.copytree(root / SOURCE_DIRECTORY, source_root, ignore=ignored)
    for directory in sorted(runtime_directories(root) | KNOWN_RUNTIME_DIRECTORIES):
        if (root / directory).is_dir():
            shutil.copytree(root / directory, workspace / directory, ignore=ignored)
    return source_root


def guard_student_file(student_file: Path, root: Path = TASK_ROOT) -> None:
    """Refuse to execute a student file the static guard rejects, naming every finding."""
    try:
        found = student_guard.findings(root / student_file)
    except student_guard.StudentGuardError as exc:
        raise MutationError(str(exc)) from exc
    if found:
        raise MutationError(
            f"{student_file.as_posix()} was not run: it must use only the supplied harness "
            "and assert each outcome (`poe student-guard`):\n- " + "\n- ".join(found)
        )


def _run_student_file(
    root: Path, student_file: Path, mutation: Mutation | None
) -> tuple[RunResult, list[dict[str, object]]]:
    """Run the student file once, as written or against one mutated copy of ``src``.

    The static guard runs first and the file is not executed when it has findings. The
    run records every action made through the harness. Under a mutation the workspace
    (``src/`` beside the directories it reads at runtime) is built in a temporary
    directory, the copy is put first on ``PYTHONPATH`` for the pytest subprocess, and the
    subprocess is asked where it imports the worker from before the tests run, so a run
    against the unmutated code can never pass as a mutated one.
    """
    guard_student_file(student_file, root)
    label = mutation.name if mutation is not None else "as written"
    changed = 0
    with tempfile.TemporaryDirectory(prefix="coldline-mutation-") as temporary:
        environment = os.environ.copy()
        if mutation is not None:
            source_root = build_workspace(root, Path(temporary))
            changed = apply_mutation(mutation.name, source_root)
            existing = environment.get("PYTHONPATH")
            environment["PYTHONPATH"] = (
                str(source_root) if not existing else os.pathsep.join([str(source_root), existing])
            )
            module = "worker.use_cases"
            probe = subprocess.run(
                [sys.executable, "-c", f"import {module}; print({module}.__file__)"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            imported = (
                Path(probe.stdout.strip()) if probe.returncode == 0 and probe.stdout else None
            )
            if imported is None or not imported.resolve().is_relative_to(source_root.resolve()):
                raise MutationError(
                    "the mutated copy was not the one imported: "
                    f"{probe.stdout.strip() or probe.stderr.strip()}"
                )
        report = Path(temporary) / "report.xml"
        recorded = Path(temporary) / "trace.jsonl"
        environment[trace.TRACE_VARIABLE] = str(recorded)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(root / student_file),
                "-q",
                "-p",
                "no:cacheprovider",
                f"--junitxml={report}",
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
        if completed.returncode not in PYTEST_VERDICT_EXITS:
            tail = (completed.stdout + completed.stderr).strip().splitlines()[-12:]
            raise MutationError(
                f"pytest exited {completed.returncode} running {student_file.as_posix()} "
                f"{label}, which is not a verdict (collection, usage, or internal error):\n"
                + "\n".join(tail)
            )
        if completed.returncode != 5 and not report.is_file():
            raise MutationError(
                f"pytest exited {completed.returncode} running {student_file.as_posix()} "
                f"{label} but wrote no junit report"
            )
        outcomes = _parse_junit(report)
        result = RunResult(label, outcomes, completed.returncode, changed)
        return result, trace.read_events(recorded)


_INVENTORIES: dict[tuple[Path, Path, str], Inventory] = {}


def collect_inventory(
    student_file: Path = STUDENT_TEST, root: Path = TASK_ROOT, *, refresh: bool = False
) -> Inventory:
    """Run the student file as written and return what each collected case did.

    The result is kept per process for the file's current content, so the assessed rows
    that share one pytest process run the inventory once.
    """
    path = root / student_file
    if not path.is_file():
        raise MutationError(f"{student_file.as_posix()} does not exist")
    content = path.read_bytes()
    try:
        ast.parse(content)
    except SyntaxError as exc:
        raise MutationError(f"{student_file.as_posix()} is not valid Python: {exc}") from exc
    key = (root.resolve(), student_file, hashlib.sha256(content).hexdigest())
    if refresh or key not in _INVENTORIES:
        result, events = _run_student_file(root, student_file, None)
        _INVENTORIES[key] = Inventory.from_run(
            student_file, result.outcomes, events, pii.limitation_ids(root)
        )
    return _INVENTORIES[key]


def run_mutation(name: str, *, root: Path = TASK_ROOT) -> RunResult:
    """Copy ``src``, apply one mutation, run the student file against the copy, and report."""
    mutation = MUTATION_TABLE.get(name)
    if mutation is None:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    result, _ = _run_student_file(root, STUDENT_TEST, mutation)
    return result


# --- Judging ------------------------------------------------------------------------------


def required_tests(name: str, inventory: Inventory) -> tuple[set[str], list[str]]:
    """Return the cases one mutation judges, and why the inventory is not yet complete."""
    problems = inventory.problems()
    if name == "note-redaction-removed":
        return inventory.note_cases, problems
    return inventory.echo_cases, problems


def judge(name: str, inventory: Inventory, result: RunResult) -> Verdict:
    """Decide whether one mutation made every required case fail on an assertion of its own.

    Only ``failed`` (an ``AssertionError``) counts: a case that still passes, was skipped,
    or produced no outcome is named, and an errored case makes the run invalid.
    """
    required, problems = required_tests(name, inventory)
    if not result.outcomes:
        problems.append(f"{STUDENT_TEST.as_posix()} produced no test cases under {name}")
    errored = sorted(
        f"{case} ({outcome.split(':', 1)[1]})" if ":" in outcome else case
        for case, outcome in result.outcomes.items()
        if outcome.startswith("error")
    )
    if errored:
        problems.append(
            f"the run under {name} is invalid: {', '.join(errored)} errored; a fixture, "
            "setup, or collection error, or an exception other than AssertionError (a missing "
            "file or module, an AttributeError or TypeError raised by the mutated copy), is "
            "not a failing assertion"
        )
    for case in sorted(required):
        outcome = result.outcomes.get(case)
        if outcome is None:
            problems.append(f"{case} produced no test case under {name}")
        elif outcome == "skipped":
            problems.append(f"{case} was skipped under {name}")
        elif outcome == "passed":
            problems.append(f"{case} still passes with {name}")
    return Verdict(name, required, problems, result.changed)


def check(name: str, *, root: Path = TASK_ROOT) -> Verdict:
    """Collect the inventory, then run one mutation against the student file and judge it.

    The structural precondition (the cases the mutation judges were executed and did what
    the file requires) is checked first, so a file without them is reported without a
    mutated run.
    """
    if name not in MUTATION_TABLE:
        raise MutationError(f"unknown mutation {name!r}; choose one of {', '.join(MUTATIONS)}")
    inventory = collect_inventory(STUDENT_TEST, root)
    required, problems = required_tests(name, inventory)
    if problems:
        return Verdict(name, required, problems)
    return judge(name, inventory, run_mutation(name, root=root))


def main() -> int:
    """Print the inventory, then run both mutations and print what each one proved."""
    exit_code = 0
    print(f"## executed cases: {STUDENT_TEST.as_posix()}\n")
    try:
        inventory = collect_inventory()
    except MutationError as exc:
        print(f"not run: {exc}\n")
        return 1
    print(inventory.describe())
    print()
    for problem in inventory.problems():
        exit_code = 1
        print(f"- {problem}")
    if inventory.problems():
        print()
    for name in MUTATIONS:
        mutation = MUTATION_TABLE[name]
        try:
            verdict = check(name)
        except MutationError as exc:
            print(f"## {name}\n\nnot run: {exc}\n")
            exit_code = 1
            continue
        print(f"## {name}\n")
        judged = ", ".join(sorted(verdict.required)) or "(none found)"
        print(f"judged: {judged} ({mutation.judged}; every case must fail)")
        if verdict.ok and verdict.changed == 0:
            print(
                f"copy: the worker has no redaction call on the {mutation.side} side; the "
                "copy ran unchanged"
            )
        elif verdict.ok:
            print(f"copy: {verdict.changed} redaction call(s) removed on the {mutation.side} side")
        if verdict.ok:
            print("verdict: proven\n")
        else:
            exit_code = 1
            print("verdict: NOT proven")
            for problem in verdict.problems:
                print(f"- {problem}")
            print()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
