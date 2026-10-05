"""Coldline.

===================

File:              tests/unit/security/test_redaction_mutation.py
Component:         Unit tests — Redaction mutations
Purpose:           Prove the transform strips one side's redaction calls and no other, the
                    mutation workspace is complete, the executed-case inventory and the judge
                    behave, and the whole path judges a student file by its assertions.
Interacts With:    tests/security/redaction_mutation.py, tests/security/trace.py,
                    src/worker/use_cases.py, docs/security/redactor.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Mutation testing, AST rewriting, evidence from executed runs, complete
                    workspaces, only assertion failures as evidence
Tools:             Python 3.12, pytest

The snippets the transform is fed are probes: a worker whose `process` calls the redactor
once before and once after the provider call, with no log line, no audit and no policy.
Most tests spawn no pytest subprocess; the one that does builds a scratch tree with a probe
worker in place of the student's module and probe tests in place of the student file, and
runs the real `check` against it, so no shipped student file is read here.
"""

from __future__ import annotations

import ast
import json
import shutil
import tomllib
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

import pytest

from tests.security import redaction_mutation as mutation
from tests.security import trace

TASK_ROOT = Path(__file__).resolve().parents[3]
STUDENT = mutation.STUDENT_TEST
LIMITATIONS = ("RL-01", "RL-02", "RL-03")

# The worker probe: one redactor call before the provider call, one after; the texts are
# returned, nothing is logged, stored or checked.
PROBE_WORKER = '''"""Worker probe."""

from common.redactor import redact
from worker.guardrail import validate_summary


class WorkerApplication:
    """Probe."""

    async def process(self, job, *, delivery_count):
        """Probe."""
        before = redact(job.reading.handling_note)
        answer = await self._provider.summarize(before)
        after = redact(answer.text)
        return validate_summary(after), before
'''


# --- The transform -------------------------------------------------------------------------


def _calls(source: str) -> list[str]:
    """Return the `redact(...)` calls a source spells, unparsed, in order."""
    return [
        ast.unparse(node)
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "redact"
    ]


def test_the_note_side_strips_the_call_before_the_provider_call_only() -> None:
    """The call before `summarize` becomes its argument; the call after it stays."""
    mutated, count = mutation.remove_redaction(PROBE_WORKER, "note")

    assert count == 1
    assert _calls(mutated) == ["redact(answer.text)"]
    assert "before = job.reading.handling_note" in mutated
    assert "validate_summary(after)" in mutated


def test_the_answer_side_strips_the_call_after_the_provider_call_only() -> None:
    """The call after `summarize` becomes its argument; the call before it stays."""
    mutated, count = mutation.remove_redaction(PROBE_WORKER, "answer")

    assert count == 1
    assert _calls(mutated) == ["redact(job.reading.handling_note)"]
    assert "after = answer.text" in mutated


def test_every_call_on_a_side_is_stripped_and_a_keyword_argument_is_kept() -> None:
    """Two calls on one side both go; `redact(text=...)` is replaced by the keyword's value."""
    doubled = PROBE_WORKER.replace(
        "        after = redact(answer.text)\n",
        "        after = redact(answer.text)\n        again = redact(text=after)\n",
    )
    mutated, count = mutation.remove_redaction(doubled, "answer")

    assert count == 2
    assert _calls(mutated) == ["redact(job.reading.handling_note)"]
    assert "again = after" in mutated


PROVIDER_LINE = "        answer = await self._provider.summarize(before)\n"
LAMBDA_PROVIDER_LINE = (
    "        answer = await self._provider.summarize(before); clean = lambda text: redact(text)\n"
)


def test_a_call_on_the_provider_line_is_classified_as_the_binding_check_reads_it() -> None:
    """The two readers share `worker_binding.call_side`: the provider line splits by position.

    A call after the provider call on its own line is the answer side (the third
    review's lambda shape: the answer mutation strips the lambda's call, the note
    mutation keeps it); a call ahead of it on that line, or inside its argument list,
    on that line or a later one, is the note side.
    """
    after = PROBE_WORKER.replace(PROVIDER_LINE, LAMBDA_PROVIDER_LINE)
    mutated, count = mutation.remove_redaction(after, "answer")
    assert count == 2
    assert _calls(mutated) == ["redact(job.reading.handling_note)"]
    assert "clean = lambda text: text" in mutated
    mutated, count = mutation.remove_redaction(after, "note")
    assert count == 1
    assert sorted(_calls(mutated)) == ["redact(answer.text)", "redact(text)"]

    ahead = PROBE_WORKER.replace(
        PROVIDER_LINE,
        "        again = redact(before); answer = await self._provider.summarize(again)\n",
    )
    mutated, count = mutation.remove_redaction(ahead, "note")
    assert count == 2
    assert _calls(mutated) == ["redact(answer.text)"]
    assert mutation.remove_redaction(ahead, "answer")[1] == 1

    inside = PROBE_WORKER.replace(
        PROVIDER_LINE, "        answer = await self._provider.summarize(redact(before))\n"
    )
    mutated, count = mutation.remove_redaction(inside, "note")
    assert count == 2
    assert "summarize(before)" in mutated
    assert _calls(mutated) == ["redact(answer.text)"]

    spread = PROBE_WORKER.replace(
        PROVIDER_LINE,
        "        answer = await self._provider.summarize(\n"
        "            redact(before),\n"
        "        )\n",
    )
    mutated, count = mutation.remove_redaction(spread, "note")
    assert count == 2
    assert _calls(mutated) == ["redact(answer.text)"]
    mutated, count = mutation.remove_redaction(spread, "answer")
    assert count == 1
    assert sorted(_calls(mutated)) == ["redact(before)", "redact(job.reading.handling_note)"]


def test_a_side_without_a_call_leaves_the_source_unchanged_with_a_zero_count() -> None:
    """A worker that never redacts on one side is already that mutation's shape."""
    note_only = PROBE_WORKER.replace(
        "        after = redact(answer.text)\n", "        after = answer.text\n"
    )
    assert mutation.remove_redaction(note_only, "answer") == (note_only, 0)
    assert mutation.remove_redaction(note_only, "note")[1] == 1

    none = PROBE_WORKER.replace("redact(", "str(")
    assert mutation.remove_redaction(none, "note") == (none, 0)
    assert mutation.remove_redaction(none, "answer") == (none, 0)


def test_a_worker_without_the_supplied_shape_is_a_tooling_error() -> None:
    """No `WorkerApplication.process`, or no provider call in it, cannot be mutated."""
    with pytest.raises(mutation.MutationError, match="defines no `WorkerApplication.process`"):
        mutation.remove_redaction("def process():\n    return redact('x')\n", "note")
    no_provider = PROBE_WORKER.replace(
        "        answer = await self._provider.summarize(before)\n", "        answer = before\n"
    )
    with pytest.raises(mutation.MutationError, match="makes no provider call"):
        mutation.remove_redaction(no_provider, "note")


def test_apply_mutation_rewrites_the_copy_and_reports_the_count(tmp_path: Path) -> None:
    """The copied worker is rewritten in place (a BOM dropped) and the count comes back."""
    source_root = tmp_path / "src"
    (source_root / "worker").mkdir(parents=True)
    bom = b"\xef\xbb\xbf"
    (source_root / "worker/use_cases.py").write_bytes(bom + PROBE_WORKER.encode("utf-8"))

    assert mutation.apply_mutation("note-redaction-removed", source_root) == 1

    rewritten = (source_root / "worker/use_cases.py").read_bytes()
    assert not rewritten.startswith(bom)
    assert _calls(rewritten.decode("utf-8")) == ["redact(answer.text)"]
    assert mutation.apply_mutation("answer-redaction-removed", source_root) == 1
    assert _calls((source_root / "worker/use_cases.py").read_text("utf-8")) == []
    assert mutation.apply_mutation("answer-redaction-removed", source_root) == 0
    with pytest.raises(mutation.MutationError, match="unknown mutation"):
        mutation.apply_mutation("header-leak", source_root)


def test_the_mutation_table_names_the_two_sides() -> None:
    """Two mutations, one per side, each judging the cases the lesson names."""
    assert set(mutation.MUTATION_TABLE) == set(mutation.MUTATIONS)
    assert mutation.MUTATION_TABLE["note-redaction-removed"].side == "note"
    assert mutation.MUTATION_TABLE["answer-redaction-removed"].side == "answer"
    assert "N-01" in mutation.MUTATION_TABLE["note-redaction-removed"].judged
    assert "pii-echo" in mutation.MUTATION_TABLE["answer-redaction-removed"].judged


# --- The workspace -------------------------------------------------------------------------


def test_the_shipped_source_reads_the_schema_and_config_directories_relative_to_itself() -> None:
    """`runtime_directories` finds every `parents[2] / "<dir>/..."` in src/: the schema first."""
    found = mutation.runtime_directories(TASK_ROOT)

    assert mutation.KNOWN_RUNTIME_DIRECTORIES <= found, found
    for directory in found:
        assert (TASK_ROOT / directory).is_dir(), directory


def test_the_workspace_copies_src_beside_every_directory_it_reads(tmp_path: Path) -> None:
    """The copy holds src/, the directories the source names, and the known ones; nothing else."""
    root = tmp_path / "root"
    (root / "src/worker").mkdir(parents=True)
    (root / "src/worker/guardrail.py").write_text(
        "from pathlib import Path\n\n"
        'SCHEMA = Path(__file__).resolve().parents[2] / "rules/a.json"\n',
        encoding="utf-8",
    )
    (root / "src/worker/__pycache__").mkdir()
    (root / "src/worker/__pycache__/guardrail.cpython-312.pyc").write_bytes(b"\x00")
    (root / "rules").mkdir()
    (root / "rules/a.json").write_text("{}\n", encoding="utf-8")
    (root / "schemas").mkdir()
    (root / "schemas/b.json").write_text("{}\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs/note.md").write_text("not copied\n", encoding="utf-8")

    assert mutation.runtime_directories(root) == {"rules"}
    source_root = mutation.build_workspace(root, tmp_path / "workspace")

    assert source_root == tmp_path / "workspace/src"
    assert (source_root / "worker/guardrail.py").is_file()
    assert not (source_root / "worker/__pycache__").exists()
    assert (tmp_path / "workspace/rules/a.json").is_file()
    assert (tmp_path / "workspace/schemas/b.json").is_file()
    assert not (tmp_path / "workspace/config").exists()
    assert not (tmp_path / "workspace/docs").exists()


# --- The inventory ----------------------------------------------------------------------


def _worker(case: str, response: str, note: str | None = None) -> dict[str, object]:
    """Return one recorded worker run, as the harness writes it."""
    return {
        "case": case,
        "kind": "worker",
        "response": response,
        "note": note,
        "exception_id": "exc-1",
    }


def _redact(case: str) -> dict[str, object]:
    """Return one recorded call of the redactor, as the harness writes it."""
    return {"case": case, "kind": "redact", "characters": 12}


def _case(name: str) -> str:
    return f"{STUDENT.as_posix()}::{name}"


def _inventory(outcomes: dict[str, str], events: list[dict[str, object]]) -> mutation.Inventory:
    return mutation.Inventory.from_run(STUDENT, outcomes, events, LIMITATIONS)


def _complete_inventory() -> mutation.Inventory:
    """Return a complete inventory: one expected-redaction case for both runs, one limitation."""
    expected, limitation = _case("test_expected"), _case("test_rl_02_probe")
    return _inventory(
        {expected: "passed", limitation: "passed"},
        [
            _worker(expected, "valid", "N-01"),
            _worker(expected, "pii-echo"),
            _redact(limitation),
        ],
    )


def test_a_complete_inventory_has_no_problems_and_knows_each_case() -> None:
    """One case ran N-01 and pii-echo, one called the redactor under a documented id."""
    inventory = _complete_inventory()
    expected, limitation = _case("test_expected"), _case("test_rl_02_probe")

    assert inventory.problems() == []
    assert inventory.note_cases == {expected}
    assert inventory.echo_cases == {expected}
    assert inventory.limitation_cases == {limitation}
    assert inventory.cases[limitation].limitation_id == "RL-02"
    assert inventory.cases[expected].limitation_id is None
    assert inventory.cases[expected].actions == (
        "ran the worker with 'valid' and the note 'N-01'",
        "ran the worker with 'pii-echo'",
    )
    assert inventory.cases[limitation].actions == ("called redact",)


def test_two_expected_redaction_cases_are_judged_each_by_their_own_mutation() -> None:
    """A case per run puts N-01 under the note mutation and pii-echo under the answer one."""
    note, echo, limitation = _case("test_n01"), _case("test_echo"), _case("test_RL-03_x")
    inventory = _inventory(
        {note: "passed", echo: "passed", limitation: "passed"},
        [_worker(note, "valid", "N-01"), _worker(echo, "pii-echo"), _redact(limitation)],
    )

    assert inventory.problems() == []
    assert mutation.required_tests("note-redaction-removed", inventory) == ({note}, [])
    assert mutation.required_tests("answer-redaction-removed", inventory) == ({echo}, [])
    assert inventory.cases[limitation].limitation_id == "RL-03"


def test_each_missing_obligation_is_named() -> None:
    """No N-01 run, no pii-echo run, no redactor call, or an unnamed limitation test is named."""
    assert _inventory({}, []).problems() == [
        f"{STUDENT.as_posix()} ran no test; write the tests the template marks"
    ]

    only_echo = _inventory({_case("test_a"): "passed"}, [_worker(_case("test_a"), "pii-echo")])
    problems = only_echo.problems()
    assert any("no test ran the worker with the note 'N-01'" in item for item in problems)
    assert any("no test called `harness.redact(...)`" in item for item in problems)
    assert not any("'pii-echo' response" in item for item in problems)

    wrong_note = _inventory(
        {_case("test_a"): "passed", _case("test_rl_01_x"): "passed"},
        [
            _worker(_case("test_a"), "valid", "N-02"),
            _worker(_case("test_a"), "pii-echo"),
            _redact(_case("test_rl_01_x")),
        ],
    )
    [problem] = wrong_note.problems()
    assert "no test ran the worker with the note 'N-01'" in problem

    unnamed = _inventory(
        {_case("test_a"): "passed", _case("test_limit"): "passed"},
        [
            _worker(_case("test_a"), "valid", "N-01"),
            _worker(_case("test_a"), "pii-echo"),
            _redact(_case("test_limit")),
        ],
    )
    [problem] = unnamed.problems()
    assert problem.startswith(
        "the limitation test must be named after the documented limitation id"
    )
    assert "RL-01, RL-02, RL-03" in problem and "test_limit" in problem

    undocumented = _inventory(
        {_case("test_a"): "passed", _case("test_rl_99_x"): "passed"},
        [
            _worker(_case("test_a"), "valid", "N-01"),
            _worker(_case("test_a"), "pii-echo"),
            _redact(_case("test_rl_99_x")),
        ],
    )
    [problem] = undocumented.problems()
    assert "must be named after the documented limitation id" in problem

    ran_worker_too = _inventory(
        {_case("test_a"): "passed", _case("test_rl_01_x"): "passed"},
        [
            _worker(_case("test_a"), "valid", "N-01"),
            _worker(_case("test_a"), "pii-echo"),
            _worker(_case("test_rl_01_x"), "valid"),
            _redact(_case("test_rl_01_x")),
        ],
    )
    [problem] = ran_worker_too.problems()
    assert "no test called `harness.redact(...)` without running the worker" in problem


def test_the_inventory_renders_as_a_table() -> None:
    """`poe redaction-mutation` prints what each case did, for the student to read."""
    table = _complete_inventory().describe()

    assert table.splitlines()[0] == "| Case | Did | Outcome |"
    did = "ran the worker with 'valid' and the note 'N-01'; ran the worker with 'pii-echo'"
    assert did in table
    assert "| called redact | passed |" in table


# --- The judge ----------------------------------------------------------------------------


def test_each_mutation_requires_every_judged_case_to_fail_and_counts_only_failed() -> None:
    """Passed, skipped and missing required cases are named; the other cases are not judged."""
    inventory = _complete_inventory()
    expected, limitation = _case("test_expected"), _case("test_rl_02_probe")

    proven = mutation.judge(
        "note-redaction-removed",
        inventory,
        mutation.RunResult(
            "note-redaction-removed", {expected: "failed", limitation: "passed"}, changed=1
        ),
    )
    assert proven.ok and proven.required == {expected} and proven.changed == 1

    weak = mutation.judge(
        "answer-redaction-removed",
        inventory,
        mutation.RunResult("answer-redaction-removed", {expected: "passed", limitation: "failed"}),
    )
    assert weak.problems == [f"{expected} still passes with answer-redaction-removed"]

    skipped = mutation.judge(
        "note-redaction-removed",
        inventory,
        mutation.RunResult("note-redaction-removed", {expected: "skipped", limitation: "passed"}),
    )
    assert skipped.problems == [f"{expected} was skipped under note-redaction-removed"]

    missing = mutation.judge("note-redaction-removed", inventory, mutation.RunResult("x", {}))
    assert any("produced no test cases" in item for item in missing.problems)
    assert any(f"{expected} produced no test case" in item for item in missing.problems)


def test_a_non_assertion_failure_is_an_invalid_run_not_a_detection() -> None:
    """A FileNotFoundError or AttributeError under a mutation invalidates the run."""
    inventory = _complete_inventory()
    expected, limitation = _case("test_expected"), _case("test_rl_02_probe")

    broken = mutation.judge(
        "note-redaction-removed",
        inventory,
        mutation.RunResult(
            "note-redaction-removed",
            {expected: "error:FileNotFoundError", limitation: "error:AttributeError"},
        ),
    )
    assert not broken.ok
    [problem] = [item for item in broken.problems if item.startswith("the run under")]
    assert f"{expected} (FileNotFoundError)" in problem
    assert f"{limitation} (AttributeError)" in problem
    assert "exception other than AssertionError" in problem


def test_check_reports_an_empty_student_file_without_mutating_anything(tmp_path: Path) -> None:
    """On a file with no tests the inventory is the whole verdict: no mutated run is made."""
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    (root / STUDENT).write_text("", encoding="utf-8")
    (root / "docs/security").mkdir(parents=True)
    (root / "docs/security/redactor.md").write_text("| RL-01 | x |\n", encoding="utf-8")

    note = mutation.check("note-redaction-removed", root=root)
    answer = mutation.check("answer-redaction-removed", root=root)

    assert not note.ok and not answer.ok
    assert note.problems == [
        "tests/student/test_redaction.py ran no test; write the tests the template marks"
    ]
    assert answer.problems == note.problems
    assert not (root / "src").exists()
    with pytest.raises(mutation.MutationError, match="unknown mutation"):
        mutation.check("validation-bypass", root=root)


def test_collect_inventory_refuses_a_missing_or_invalid_student_file(tmp_path: Path) -> None:
    """A missing file and a syntax error are tooling errors with the file named."""
    with pytest.raises(mutation.MutationError, match="does not exist"):
        mutation.collect_inventory(STUDENT, tmp_path)
    (tmp_path / "tests/student").mkdir(parents=True)
    (tmp_path / STUDENT).write_text("def (:\n", encoding="utf-8")
    with pytest.raises(mutation.MutationError, match="not valid Python"):
        mutation.collect_inventory(STUDENT, tmp_path)


def test_a_student_file_the_guard_rejects_is_never_executed(tmp_path: Path) -> None:
    """The counterexample is refused by the inventory and by its mutation: nothing runs."""
    root = tmp_path
    (root / "tests/student").mkdir(parents=True)
    (root / "docs/security").mkdir(parents=True)
    (root / "docs/security/redactor.md").write_text("| RL-01 | x |\n", encoding="utf-8")
    (root / STUDENT).write_text(
        "import pytest\nimport worker.use_cases\n\nORIGINAL = worker.use_cases.__file__\n"
        "\n\nasync def test_n01(harness):\n"
        '    await harness.run_worker("valid", note="N-01")\n'
        "    assert worker.use_cases.__file__ == ORIGINAL\n",
        encoding="utf-8",
    )

    with pytest.raises(mutation.MutationError, match="was not run") as refused:
        mutation.collect_inventory(STUDENT, root)
    message = str(refused.value)
    assert "`import worker.use_cases` is not permitted" in message
    assert "`__file__` is not permitted" in message
    assert "`test_n01` has no `assert` over a value obtained from the harness" in message
    with pytest.raises(mutation.MutationError, match="was not run"):
        mutation.check("note-redaction-removed", root=root)
    assert not (root / "src").exists()
    assert not list(root.glob("**/report.xml"))


# --- Case identities and junit outcomes ------------------------------------------------------


def _report(path: Path, rows: list[tuple[str, str, str, str]]) -> Path:
    """Write a junit report: (classname, name, outcome element or "", message)."""
    cases = "".join(
        f"<testcase classname='{classname}' name='{name}' time='0.1'>"
        + (
            f"<{outcome} message={quoteattr(message)}>{escape(message)}</{outcome}>"
            if outcome
            else ""
        )
        + "</testcase>"
        for classname, name, outcome, message in rows
    )
    path.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        + cases
        + "</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def test_parse_junit_keeps_same_named_methods_apart_and_rejects_duplicates(tmp_path: Path) -> None:
    """Two classes' `test_x` are two outcomes; one identity twice is a tooling error."""
    module = "tests.student.test_redaction"
    report = tmp_path / "report.xml"

    outcomes = mutation._parse_junit(
        _report(
            report,
            [
                (f"{module}.TestWeak", "test_x", "", ""),
                (f"{module}.TestStrong", "test_x", "failure", "assert 1 == 2"),
                (module, "test_y", "error", "fixture 'x' not found"),
                (module, "test_z", "skipped", "skipped"),
            ],
        )
    )
    assert outcomes == {
        f"{STUDENT.as_posix()}::TestWeak::test_x": "passed",
        f"{STUDENT.as_posix()}::TestStrong::test_x": "failed",
        f"{STUDENT.as_posix()}::test_y": "error",
        f"{STUDENT.as_posix()}::test_z": "skipped",
    }
    with pytest.raises(mutation.MutationError, match="twice"):
        mutation._parse_junit(
            _report(report, [(module, "test_x", "", ""), (module, "test_x", "failure", "x")])
        )
    assert mutation._parse_junit(tmp_path / "absent.xml") == {}


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/x/schemas/s.json'",
            "error:FileNotFoundError",
        ),
        ("ModuleNotFoundError: No module named 'common.redactor'", "error:ModuleNotFoundError"),
        ("AttributeError: 'NoneType' object has no attribute 'text'", "error:AttributeError"),
        ("TypeError: expected string or bytes-like object", "error:TypeError"),
        ("Failed: DID NOT RAISE <class 'KeyError'>", "error:Failed"),
        ("AssertionError: a marked value reached the logs\nassert [] == ['x']", "failed"),
        ("AssertionError", "failed"),
        ("assert ['worker logs: N-01 phone'] == []", "failed"),
        ("assert not True", "failed"),
        ("assertion_helper.Error: x", "error:Error"),
    ],
    ids=[
        "file",
        "module",
        "attribute",
        "type",
        "did-not-raise",
        "assertion-message",
        "bare-assertion",
        "rewritten-assert",
        "rewritten-not",
        "dotted-lookalike",
    ],
)
def test_only_an_assertion_failure_is_a_failed_outcome(
    tmp_path: Path, message: str, expected: str
) -> None:
    """A junit failure is `failed` only for `AssertionError`; any other is an error by name."""
    report = _report(
        tmp_path / "report.xml",
        [("tests.student.test_redaction", "test_expected", "failure", message)],
    )

    assert mutation._parse_junit(report) == {f"{STUDENT.as_posix()}::test_expected": expected}


def test_the_failure_exception_is_read_from_the_type_attribute_or_the_texts_last_line(
    tmp_path: Path,
) -> None:
    """A `type` attribute wins; with no usable message, the traceback's `path:line: Name`."""
    report = tmp_path / "report.xml"
    report.write_text(
        "<?xml version='1.0'?><testsuites><testsuite name='pytest'>"
        "<testcase classname='tests.student.test_redaction' name='test_typed'>"
        "<failure type='builtins.AttributeError' message='assert 1 == 1'>x</failure></testcase>"
        "<testcase classname='tests.student.test_redaction' name='test_located'>"
        "<failure message=''>def test_located():\n&gt;       assert found == []\n"
        "E       assert ['x'] == []\n\ntests/student/test_redaction.py:40: AssertionError"
        "</failure></testcase>"
        "<testcase classname='tests.student.test_redaction' name='test_unknown'>"
        "<failure message=''></failure></testcase>"
        "</testsuite></testsuites>",
        encoding="utf-8",
    )

    assert mutation._parse_junit(report) == {
        f"{STUDENT.as_posix()}::test_typed": "error:AttributeError",
        f"{STUDENT.as_posix()}::test_located": "failed",
        f"{STUDENT.as_posix()}::test_unknown": "error:unknown",
    }


def test_trace_names_the_current_case_by_its_full_node_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The recorded case is the full node id: the student file, the class chain, the name."""
    monkeypatch.setenv(
        trace.CURRENT_TEST_VARIABLE, f"{STUDENT.as_posix()}::TestA::test_y[a-b] (call)"
    )
    assert trace.current_case() == f"{STUDENT.as_posix()}::TestA::test_y[a-b]"
    monkeypatch.setenv(trace.CURRENT_TEST_VARIABLE, "test_redaction.py::test_z (setup)")
    assert trace.current_case() == f"{STUDENT.as_posix()}::test_z"
    monkeypatch.delenv(trace.CURRENT_TEST_VARIABLE)
    assert trace.current_case() == ""

    recorded = tmp_path / "trace.jsonl"
    trace.record(None, {"kind": "redact"})
    trace.record(recorded, {"kind": "worker", "response": "valid", "note": "N-01"})
    [event] = trace.read_events(recorded)
    assert event == {"case": "", "kind": "worker", "note": "N-01", "response": "valid"}


# --- The whole path, against probe modules ----------------------------------------------------

PROBE_WORKER_MODULE = '''"""Probe worker: redacts the note and the answer, stores the text."""

from enum import StrEnum

from common.redactor import redact
from domain.contracts import ExceptionState, ModelRequest
from worker.guardrail import validate_summary


class ProcessingDisposition(StrEnum):
    """One acknowledgement."""

    ACK = "ACK"


class WorkerApplication:
    """The smallest worker the harness can run; it implements no output policy."""

    def __init__(self, repository, provider, procedures, *, audit, clock, maximum_attempts=3):
        """Keep the collaborators the harness hands over."""
        self._repository = repository
        self._provider = provider
        self._procedures = procedures

    async def process(self, job, *, delivery_count):
        """Redact the note into the request and the answer into the stored text; check nothing."""
        await self._repository.transition(
            job.exception_id, {ExceptionState.QUEUED}, ExceptionState.PROCESSING
        )
        procedure = await self._procedures.find(job.reading)
        note = redact(job.reading.handling_note)
        answer = await self._provider.summarize(
            ModelRequest(
                exception_id=job.exception_id,
                shipment_id=job.reading.shipment_id,
                temperature_c=job.reading.temperature_c,
                allowed_min_c=job.reading.allowed_min_c,
                allowed_max_c=job.reading.allowed_max_c,
                handling_note=note,
                procedure_id=procedure.document_id,
                procedure_excerpt=procedure.text,
                emulator_response=job.reading.emulator_response,
            )
        )
        text = redact(answer.text)
        validate_summary(text)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=text,
        )
        return ProcessingDisposition.ACK
'''

PROBE_HEADER = '''"""Probe redaction tests."""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API."""
    return InteractionHarness()


def test_rl_01_probe(harness: InteractionHarness) -> None:
    """A probe limitation test: the redactor's output on a probe phrase."""
    assert harness.redact("call 555-0100") == "call [REDACTED:phone]"
'''

NOOP_TESTS = (
    PROBE_HEADER
    + '''

async def test_both_runs(harness: InteractionHarness) -> None:
    """Runs both; asserts nothing about the four locations."""
    note_run = await harness.run_worker("valid", note="N-01")
    echo_run = await harness.run_worker("pii-echo")
    assert note_run.state == "COMPLETED"
    assert echo_run.state == "COMPLETED"
'''
)

ASSERTING_TESTS = (
    PROBE_HEADER
    + '''

async def test_both_runs(harness: InteractionHarness) -> None:
    """Runs both; asserts the four locations are clean."""
    note_run = await harness.run_worker("valid", note="N-01")
    echo_run = await harness.run_worker("pii-echo")
    assert harness.pii_findings(note_run.exception_id, note="N-01") == []
    assert harness.pii_findings(echo_run.exception_id, response="pii-echo") == []
'''
)
PROBE_DIRECTORIES = (
    "src",
    "schemas",
    "config",
    "tests/security",
    "tests/doubles",
    "tests/fixtures",
    "infra/corpus",
)
PROBE_FILES = (
    "tests/__init__.py",
    "tests/e2e/baseline-exception.json",
    "docs/security/redactor.md",
)


def _probe_root(tmp_path: Path) -> Path:
    """Build a scratch Task tree: the shipped tooling and shared code, a probe worker module.

    The real ``src/`` is copied, then the student-editable worker is replaced by the probe,
    so no shipped student file is read or run by this test.
    """
    root = tmp_path / "root"
    for relative in PROBE_DIRECTORIES:
        shutil.copytree(
            TASK_ROOT / relative,
            root / relative,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for relative in PROBE_FILES:
        if (TASK_ROOT / relative).is_file():
            (root / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(TASK_ROOT / relative, root / relative)
    options = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "pytest"
    ]["ini_options"]
    (root / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        + "".join(f"{key} = {json.dumps(value)}\n" for key, value in options.items()),
        encoding="utf-8",
    )
    (root / "src/worker/use_cases.py").write_text(PROBE_WORKER_MODULE, encoding="utf-8")
    (root / "tests/student").mkdir(parents=True, exist_ok=True)
    return root


def test_the_mutations_are_judged_by_the_tests_assertions_in_a_complete_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Against a complete copy, a no-op test survives both mutations; an asserting one fails both.

    Both runs go through the real `check`: the inventory run as written, then the mutated
    run against a workspace that holds `schemas/` and `config/` beside the mutated `src/`.
    The probe worker redacts the note into the request and the answer into the stored
    text, so as written the scan is clean; with the note call stripped the request carries
    N-01's values, with the answer call stripped the stored text carries the pii-echo
    contact. The no-op test passes under both and the verdict names it; the asserting
    test fails under both with an assertion of its own and proves them.
    """
    root = _probe_root(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(root / "src"))
    monkeypatch.delenv(trace.TRACE_VARIABLE, raising=False)
    case = f"{STUDENT.as_posix()}::test_both_runs"

    (root / STUDENT).write_text(NOOP_TESTS, encoding="utf-8")
    for name in mutation.MUTATIONS:
        insufficient = mutation.check(name, root=root)
        assert insufficient.required == {case}
        assert not insufficient.ok
        assert insufficient.problems == [f"{case} still passes with {name}"]
        assert insufficient.changed == 1

    (root / STUDENT).write_text(ASSERTING_TESTS, encoding="utf-8")
    for name in mutation.MUTATIONS:
        proven = mutation.check(name, root=root)
        assert proven.required == {case}
        assert proven.ok, proven.problems
        assert proven.changed == 1
