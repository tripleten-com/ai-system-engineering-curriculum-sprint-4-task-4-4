"""Coldline.

===================

File:              tests/unit/security/test_student_guard.py
Component:         Unit tests — Static student-test guard
Purpose:           Prove the guard accepts tests that describe outcomes and rejects every way a
                    test could inspect its environment instead, before any execution.
Interacts With:    tests/security/student_guard.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Trusted static analysis, closed import set, flat name rules, assertions
                    over outcomes
Tools:             Python 3.12, pytest, tomllib

Every test here feeds a synthetic source to the guard; none reads the shipped student
file, whose state is the student's (the assessed row and `poe student-guard` read it).
The synthetic sources are probes, the smallest tests that satisfy or break one rule: a
redaction test that asserts the scan of one run is clean, a test that pins the redactor's
output on a probe phrase; none shows the Task's own answers. The authoring suite checks the
shipped template and the private completions separately. One test runs the real
`poe student-tests` sequence in a scratch project, to prove a rejected file's module-level
code never executes through that command. The snippets that spell `eval`, `__file__`,
`ForwardRef` or `pytest.fixture` are source text handed to the parser; nothing here
executes them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tomllib
from pathlib import Path

import pytest

from tests.security import student_guard

TASK_ROOT = Path(__file__).resolve().parents[3]
RULES = student_guard.STUDENT_FILES["test_redaction.py"]

HEADER = '''"""Student tests."""

import pytest

from tests.security.interaction import InteractionHarness


@pytest.fixture
def harness() -> InteractionHarness:
    """Return a fresh in-process worker and API."""
    return InteractionHarness()
'''

REDACTION_TEST = '''

async def test_marked_values_reach_nowhere(harness: InteractionHarness) -> None:
    """The run leaves no marked value anywhere."""
    record = await harness.run_worker("valid", note="N-01")

    assert harness.pii_findings(record.exception_id, note="N-01") == []
'''

PINNED_TEST = '''

def test_the_redactor_output_is_pinned(harness: InteractionHarness) -> None:
    """A phone number in a probe phrase is replaced."""
    redacted = harness.redact("call 555-0100")

    assert redacted == "call [REDACTED:phone]"
'''

ACCEPTED = HEADER + REDACTION_TEST + PINNED_TEST
FINDINGS_ASSERT = '    assert harness.pii_findings(record.exception_id, note="N-01") == []\n'
SIGNATURE = '(harness: InteractionHarness) -> None:\n    """The run leaves'
RENAME = "rename it, for example to `resp`"


def _guard(source: str | bytes) -> list[str]:
    return student_guard.findings_for_source(source, RULES)


def _line_of(source: str, needle: str) -> int:
    """Return the 1-based line of the first line containing ``needle``."""
    return next(number for number, line in enumerate(source.splitlines(), 1) if needle in line)


def _named(found: list[str], name: str) -> list[int]:
    """Return the lines on which ``name`` is reported as a forbidden name."""
    prefix = "line "
    return [
        int(finding[len(prefix) :].split(":", 1)[0])
        for finding in found
        if finding.startswith(prefix)
        and f"`{name}` is not permitted in the student file" in finding
    ]


def _file_counterexample() -> str:
    """Return the counterexample: a test that asserts where the worker module lives.

    It runs the worker with N-01, as the inventory requires, and then asserts only that
    the imported worker module belongs to the original checkout. As written it passes;
    under a mutation the copy lives elsewhere, so it fails; and it says nothing about any
    record or any location.
    """
    return HEADER + (
        "\nimport worker.use_cases\n\nORIGINAL = worker.use_cases.__file__\n"
        "\n\nasync def test_n01(harness: InteractionHarness) -> None:\n"
        '    """Run N-01, then look at the environment."""\n'
        '    await harness.run_worker("valid", note="N-01")\n'
        "    assert worker.use_cases.__file__ == ORIGINAL\n"
    )


def test_the_template_shape_with_no_tests_passes_vacuously() -> None:
    """The shipped template's shape (imports, the fixture, no tests) has nothing to report.

    The executed-case inventory is what requires the tests; the guard only refuses files
    that must not be executed, and an empty one is harmless to run.
    """
    assert _guard(HEADER) == []
    assert _guard("") == []


def test_tests_that_describe_outcomes_are_accepted() -> None:
    """A redaction test asserting over the scan, and a test over the redactor, pass the rules."""
    assert _guard(ACCEPTED) == []
    assert _guard(ACCEPTED.encode("utf-8")) == []


def test_a_test_that_asserts_over_nothing_from_the_harness_is_named() -> None:
    """An assert over a literal, or over a value the test built, is not an assert over the run."""
    found = _guard(
        HEADER + "\n\nasync def test_nothing(harness: InteractionHarness) -> None:\n"
        '    """Runs, then asserts a constant."""\n'
        '    await harness.run_worker("valid", note="N-01")\n'
        "    assert 1 == 1\n"
    )
    assert found == [
        "`test_nothing` has no `assert` over a value obtained from the harness: assert over the "
        "record from `harness.run_worker(...)`, over `harness.pii_findings(...)`, "
        "`harness.worker_logs(...)`, `harness.model_request(...)`, "
        "`harness.expected_summary(...)`, `harness.audit_trail(...)` or "
        "`harness.audit_text(...)`, or over `harness.redact(...)`"
    ]


def test_the_counterexample_is_rejected_before_any_execution() -> None:
    """A test asserting `worker.use_cases.__file__` is named three ways and never run."""
    found = _guard(_file_counterexample())

    assert any("`import worker.use_cases` is not permitted" in finding for finding in found)
    assert sum("`__file__` is not permitted" in finding for finding in found) == 2
    missing = [finding for finding in found if "has no `assert` over a value" in finding]
    assert len(missing) == 1


@pytest.mark.parametrize(
    "snippet, name",
    [
        ("    import sys\n    assert 'pytest' in sys.modules\n", "sys"),
        ("    assert getattr(record, 'state') == 'COMPLETED'\n", "getattr"),
        ("    assert open('config/auth.yaml').read()\n", "open"),
        ("    assert eval('1') == 1\n", "eval"),
        ("    assert __import__('os')\n", "__import__"),
        ("    assert record.__class__.__module__\n", "__class__"),
        ("    assert harness.root\n", "root"),
        ("    assert harness.repository\n", "repository"),
        ("    assert harness._audit\n", "_audit"),
        ("    assert harness._request_log\n", "_request_log"),
        ("    assert harness._logs\n", "_logs"),
        ("    assert harness._notes\n", "_notes"),
        ("    assert harness.run_worker.__code__.co_filename\n", "__code__"),
        ("    import importlib\n    assert importlib\n", "importlib"),
        ("    from pathlib import Path\n    assert Path('x')\n", "Path"),
        ("    assert __spec__.origin\n", "__spec__"),
        ("    assert delattr(harness, 'root') is None\n", "delattr"),
        ("    assert ForwardRef('1')\n", "ForwardRef"),
        ("    assert get_type_hints(harness)\n", "get_type_hints"),
    ],
)
def test_each_forbidden_name_or_attribute_is_named_by_line(snippet: str, name: str) -> None:
    """A forbidden name as a Name, an Attribute, or an import binding is one finding by line."""
    source = ACCEPTED.replace(FINDINGS_ASSERT, snippet + FINDINGS_ASSERT, 1)
    found = _guard(source)

    assert any(f"`{name}` is not permitted in the student file" in finding for finding in found), (
        found
    )
    assert all(finding.startswith("line ") for finding in found if "not permitted" in finding)


def test_forbidden_names_are_rejected_wherever_they_appear_with_no_binding_exemption() -> None:
    """A binding does not make a forbidden name ordinary: every position is a finding."""
    module_level = HEADER + "\neval = eval\nenvironment = eval('globals()')\n" + REDACTION_TEST
    found = _guard(module_level)
    assert _named(found, "eval") == [
        _line_of(module_level, "eval = eval"),
        _line_of(module_level, "environment = eval"),
    ]
    assert [finding for finding in found if "not permitted" not in finding] == []

    every_position = ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import Any as os\n\n\ndef Path(sys, *subprocess, **inspect):\n"
        '    """Named after what it may not be."""\n    global vars\n    return 0\n\n\n'
        'class compile:\n    """Named after what it may not be."""\n',
    ).replace(
        FINDINGS_ASSERT,
        "    for open in (1,):\n        pass\n"
        "    with harness.bearer_client('expired') as globals:\n        pass\n"
        "    resolve = lambda getattr: getattr\n"
        "    try:\n        pass\n    except Exception as builtins:\n        pass\n"
        + FINDINGS_ASSERT,
    )
    found = _guard(every_position)
    names = {
        finding.split("`")[1]
        for finding in found
        if "is not permitted in the student file" in finding
    }
    assert names == {
        "os",
        "Path",
        "sys",
        "subprocess",
        "inspect",
        "vars",
        "compile",
        "open",
        "globals",
        "getattr",
        "builtins",
    }
    assert not _named(found, "resolve")


@pytest.mark.parametrize(
    "snippet",
    [
        '    assert "{0.run_worker.__func__.__globals__[WorkerApplication].process.__code__'
        '.co_filename}".format(harness)\n',
        '    assert "{0.app.routes[4].endpoint.__code__.co_filename}".format(harness)\n',
        '    assert "{h.app.routes[4].endpoint.__code__.co_filename}".format_map({"h": harness})\n',
        '    render = "{0.root}".format\n    assert render(harness)\n',
        '    assert str.format("{0.__class__.__module__}", record)\n',
    ],
    ids=["worker-file", "route-file", "format-map", "alias", "str-format"],
)
def test_a_format_field_traversal_is_rejected_by_its_attribute(snippet: str) -> None:
    """`.format` and `.format_map` are findings: a format field traverses attributes in a string.

    The guard cannot see inside a string constant; the attribute that applies the
    template is the one spelled thing, and it is refused. An f-string stays permitted
    because its expressions are AST the name rules inspect.
    """
    source = ACCEPTED.replace(FINDINGS_ASSERT, snippet + FINDINGS_ASSERT, 1)
    found = _guard(source)

    assert any(
        "`format` is not permitted in the student file" in finding
        or "`format_map` is not permitted in the student file" in finding
        for finding in found
    ), found
    assert all(finding.startswith("line ") for finding in found if "not permitted" in finding)

    f_string = ACCEPTED.replace(
        FINDINGS_ASSERT,
        '    assert f"{record.exception_id}: {record.state}"\n' + FINDINGS_ASSERT,
        1,
    )
    assert _guard(f_string) == []
    traversing_f_string = ACCEPTED.replace(
        FINDINGS_ASSERT, '    assert f"{harness.run_worker.__func__}"\n' + FINDINGS_ASSERT, 1
    )
    assert _named(_guard(traversing_f_string), "__func__")
    builtin = ACCEPTED.replace(
        FINDINGS_ASSERT, '    assert format(9.2, ".1f") == "9.2"\n' + FINDINGS_ASSERT, 1
    )
    assert _guard(builtin) == []


def test_a_custom_assertion_error_is_rejected_as_a_builtin_binding() -> None:
    """The third review's file: `class AssertionError(RuntimeError)` raised on a condition.

    The mutation judge reads a failing case's exception from the junit report by its
    name, so a same-named class of the file's own would count a conditional `raise` as a
    detection no assertion made. The file otherwise passes the other five rules (it
    asserts over the record), and the one finding is the binding, by line.
    """
    source = HEADER + (
        "\n\nclass AssertionError(RuntimeError):\n"
        '    """Not the builtin: raised when the file decides to."""\n'
        "\n\nasync def test_n01(harness: InteractionHarness) -> None:\n"
        '    """Run N-01, assert the state, and raise the custom exception on a condition."""\n'
        '    record = await harness.run_worker("valid", note="N-01")\n'
        '    assert record.state == "COMPLETED"\n'
        '    if harness.pii_findings(record.exception_id, note="N-01"):\n'
        '        raise AssertionError("found")\n'
    )
    [finding] = _guard(source)
    assert finding == (
        f"line {_line_of(source, 'class AssertionError')}: `AssertionError` is a Python "
        f"builtin, and binding one is not permitted in the student file; "
        f"{student_guard.BUILTIN_HINT}"
    )
    # Raising or catching the builtin is not a binding.
    raising = ACCEPTED.replace(
        FINDINGS_ASSERT,
        "    if record.state != 'COMPLETED':\n        raise AssertionError\n" + FINDINGS_ASSERT,
    )
    assert _guard(raising) == []


@pytest.mark.parametrize(
    ("snippet", "name"),
    [
        ("    len = 3\n", "len"),
        ("    id: int = 1\n", "id"),
        ("    sum += 1\n", "sum"),
        ("    (type := record.state)\n", "type"),
        ("    for id in (1,):\n        pass\n", "id"),
        ("    with pytest.raises(KeyError) as max:\n        {}['x']\n", "max"),
        ("    first = [len for len in (1,)]\n", "len"),
        ("    name_of = lambda abs: abs\n", "abs"),
        ("    try:\n        pass\n    except Exception as range:\n        pass\n", "range"),
        ("    global hex\n", "hex"),
        ("    match record.state:\n        case list:\n            pass\n", "list"),
        ("    del dict\n", "dict"),
    ],
    ids=[
        "assign",
        "annotated",
        "augmented",
        "walrus",
        "for",
        "with",
        "comprehension",
        "lambda-parameter",
        "handler",
        "global",
        "match",
        "del",
    ],
)
def test_every_binding_of_a_builtin_name_is_named_by_line(snippet: str, name: str) -> None:
    """A builtin bound as a target, a parameter, a handler, a capture or a `global` is a finding."""
    source = ACCEPTED.replace(FINDINGS_ASSERT, snippet + FINDINGS_ASSERT, 1)
    found = _guard(source)
    [finding] = [item for item in found if "is a Python builtin, and binding one" in item]
    first = _line_of(source, snippet.splitlines()[0].strip())
    reported = int(finding[len("line ") :].split(":", 1)[0])
    assert first <= reported < first + len(snippet.splitlines()), finding
    assert finding.split(": ", 1)[1].startswith(f"`{name}` is a Python builtin"), finding


def test_builtin_names_bound_at_module_level_by_definitions_and_imports_are_named() -> None:
    """A function, a class, a parameter, an import alias and an imported name are bindings too."""
    source = (
        HEADER
        + (
            "\nfrom typing import Any as str\n\n\n"
            "def print(record, *, len) -> None:\n"
            '    """Named after what it may not be."""\n'
            "    return None\n\n\n"
            "class open:\n"
            '    """Named after what it may not be."""\n'
        )
        + REDACTION_TEST
    )
    found = _guard(source)
    names = [
        finding.split("`")[1]
        for finding in found
        if "is a Python builtin, and binding one" in finding
    ]
    assert names == ["str", "print", "len", "open"]
    # `open` is on the forbidden list as well: that rule names it too, this one once.
    assert _named(found, "open") == [_line_of(source, "class open")]
    assert "harness" not in student_guard.BUILTIN_NAMES
    assert "_" not in student_guard.BUILTIN_NAMES
    assert {"AssertionError", "print", "open", "len", "isinstance", "id"} <= (
        student_guard.BUILTIN_NAMES
    )
    # The private shapes a test needs are not bindings of a builtin: reading one is fine.
    reading = ACCEPTED.replace(
        FINDINGS_ASSERT,
        "    assert isinstance(record.summary, str) and len(record.summary)\n" + FINDINGS_ASSERT,
    )
    assert _guard(reading) == []


def test_a_local_named_like_a_harness_internal_is_accepted_but_the_attribute_is_not() -> None:
    """`records = harness.audit_trail(id)` is the file's own variable; `harness.records` is not."""
    local = ACCEPTED.replace(
        FINDINGS_ASSERT,
        "    records = harness.audit_trail(record.exception_id)\n    assert records is not None\n",
    )
    assert _guard(local) == []
    attribute = ACCEPTED.replace(
        FINDINGS_ASSERT, "    trail = harness.repository.records\n    assert trail\n"
    )
    found = _guard(attribute)
    assert any("`repository`" in finding for finding in found)
    assert any("`records`" in finding for finding in found)


def test_every_dunder_is_rejected_as_an_attribute_or_a_name() -> None:
    """`x.__class__`, and any other dunder, is a finding wherever it is."""
    source = ACCEPTED.replace(
        FINDINGS_ASSERT,
        "    __file__ = 'x'\n"
        "    assert record.__class__\n"
        "    assert InteractionHarness.__module__\n"
        "    assert __name__\n" + FINDINGS_ASSERT,
    )
    found = _guard(source)
    assert [finding.split(": ", 1)[0] for finding in found] == [
        f"line {_line_of(source, '__file__ = ')}",
        f"line {_line_of(source, 'assert record.__class__')}",
        f"line {_line_of(source, 'assert InteractionHarness.__module__')}",
        f"line {_line_of(source, 'assert __name__')}",
    ]


def test_imports_outside_the_four_permitted_forms_are_rejected_wherever_they_appear() -> None:
    """Only `import pytest`, the annotations future, permitted typing names and the harness."""
    accepted_imports = (
        "from __future__ import annotations\n"
        "from typing import Any\n"
        "from typing import cast as typing_cast\n"
        "import pytest\n"
        "from tests.security.interaction import InteractionHarness\n"
    )
    assert _guard(accepted_imports) == []

    for statement in (
        "import os\n",
        "import httpx\n",
        "import typing\n",
        "import pytest as pt\n",
        "import worker.use_cases\n",
        "from pytest import fixture\n",
        "from __future__ import division\n",
        "from typing import ForwardRef\n",
        "from typing import get_type_hints\n",
        "from typing import *\n",
        "from typing import NewType\n",
        "from tests.security import interaction\n",
        "from tests.security import pii\n",
        "from tests.security.harness import AccessHarness\n",
        "from tests.security.interaction import planted_excerpt\n",
        "from tests.security.interaction import InteractionHarness as Harness\n",
        "from tests.security.redaction_mutation import check\n",
        "from common.redactor import redact\n",
        "from . import conftest\n",
    ):
        [finding] = [item for item in _guard(statement) if "the only imports are" in item]
        assert finding.startswith("line 1: ") and statement.strip() in finding, statement


def test_typing_imports_are_limited_to_the_annotation_allowlist() -> None:
    """Every name on the allowlist passes; every other `typing` name fails the import rule."""
    for name in sorted(student_guard.TYPING_NAMES):
        assert _guard(f"from typing import {name}\n") == [], name
        assert _guard(f"from typing import {name} as permitted_{name}\n") == [], name
    assert student_guard.TYPING_NAMES == {
        "Any",
        "Annotated",
        "Literal",
        "Optional",
        "Union",
        "cast",
        "TYPE_CHECKING",
        "Final",
    }

    found = _guard("from typing import Any, ForwardRef\n")
    [imported] = [item for item in found if "the only imports are" in item]
    assert "`from typing import ForwardRef` is not permitted" in imported
    assert "Any" not in imported.split(" is not permitted")[0]
    assert any("`ForwardRef` is not permitted in the student file" in item for item in found)

    for name in ("get_type_hints", "get_args", "get_origin", "NewType", "TypeVar", "Protocol"):
        found = _guard(f"from typing import {name}\n")
        assert any(f"`from typing import {name}` is not permitted" in item for item in found), name


def test_an_annotation_string_handed_to_an_evaluator_is_rejected_before_it_runs() -> None:
    """`ForwardRef(...)._evaluate(...)` and `get_type_hints(...)` over a string are findings."""
    forward_ref = ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import ForwardRef\n\n"
        "MARKER = ForwardRef(\"__import__('os').getcwd()\")._evaluate({}, {}, frozenset())\n",
    )
    found = _guard(forward_ref)
    assert any("`from typing import ForwardRef` is not permitted" in item for item in found)
    assert _named(found, "ForwardRef") == [
        _line_of(forward_ref, "from typing import ForwardRef"),
        _line_of(forward_ref, "MARKER = "),
    ]
    assert _named(found, "_evaluate") == [_line_of(forward_ref, "MARKER = ")]
    assert "`__import__`" not in "".join(found)

    hints = ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import get_type_hints\n\n\n"
        "def probe(value: \"__import__('os').getcwd()\") -> None:\n"
        '    """Carry an annotation string."""\n\n\n'
        "HINTS = get_type_hints(probe)\n",
    )
    found = _guard(hints)
    assert any("`from typing import get_type_hints` is not permitted" in item for item in found)
    assert _named(found, "get_type_hints") == [
        _line_of(hints, "from typing import get_type_hints"),
        _line_of(hints, "HINTS = "),
    ]

    star = ACCEPTED.replace(HEADER, HEADER + "\nfrom typing import *\n")
    assert any("`from typing import *` is not permitted" in item for item in _guard(star))


def test_pytest_is_used_only_as_fixture_decorator_the_two_marks_param_and_raises() -> None:
    """`pytest.fixture` assigned to a name is rejected, as is any other door."""
    accepted = HEADER + (
        "\n\n@pytest.mark.parametrize(\n"
        '    "response, state",\n'
        '    [pytest.param("valid", "COMPLETED", id="valid", marks=pytest.mark.asyncio),\n'
        '     pytest.param("pii-echo", "COMPLETED", id="echo")],\n'
        ")\n"
        "async def test_each(harness: InteractionHarness, response: str, state: str) -> None:\n"
        '    """One case per response."""\n'
        "    record = await harness.run_worker(response)\n"
        "    with pytest.raises(KeyError):\n"
        '        {}["summary"]\n'
        "    assert record.state == state\n"
    )
    assert _guard(accepted) == []

    for snippet, named in (
        ("fixture = pytest.fixture\n", "`pytest.fixture` is permitted only as a decorator"),
        ("skip = pytest.importorskip('os')\n", "`pytest.importorskip` is not permitted"),
        ("patcher = pytest.MonkeyPatch()\n", "`pytest.MonkeyPatch` is not permitted"),
        ("p = pytest\n", "`pytest` on its own is not permitted"),
        ("m = pytest.mark\n", "`pytest.mark` is not permitted"),
        (
            "@pytest.mark.skipif('mutated = True', reason='x')\ndef helper() -> None:\n"
            "    return None\n",
            "`pytest.mark.skipif` is not permitted",
        ),
        ("flag = pytest.param(1, marks=pytest.mark.xfail)\n", "`pytest.mark.xfail` is not"),
    ):
        source = HEADER + "\n" + snippet + REDACTION_TEST
        found = _guard(source)
        assert len(found) == 1 and named in found[0], (snippet, found)


@pytest.mark.parametrize("shape", ["test", "fixture", "module helper", "nested function", "lambda"])
def test_a_reserved_parameter_name_is_rejected_on_every_kind_of_function(shape: str) -> None:
    """No function takes `request`, `monkeypatch`, `tmp_path`, or another built-in fixture name."""
    if shape == "test":
        source = ACCEPTED.replace(
            SIGNATURE, '(harness: InteractionHarness, request) -> None:\n    """The run leaves'
        )
        function = "test_marked_values_reach_nowhere"
    elif shape == "fixture":
        source = (
            HEADER
            + (
                "\n\n@pytest.fixture\ndef message(request) -> str:\n"
                '    """A fixture asking for pytest\'s request."""\n    return "x"\n'
            )
            + REDACTION_TEST
        )
        function = "message"
    elif shape == "module helper":
        source = (
            HEADER
            + (
                "\n\ndef clean(request) -> None:\n"
                '    """Assert nothing was found."""\n'
                "    assert request == []\n"
            )
            + REDACTION_TEST.replace(
                FINDINGS_ASSERT,
                '    clean(harness.pii_findings(record.exception_id, note="N-01"))\n',
            )
        )
        function = "clean"
    elif shape == "nested function":
        source = HEADER + REDACTION_TEST.replace(
            FINDINGS_ASSERT,
            "    def check(request):\n"
            "        assert request == []\n\n"
            '    check(harness.pii_findings(record.exception_id, note="N-01"))\n',
        )
        function = "check"
    else:
        source = ACCEPTED.replace(
            FINDINGS_ASSERT, "    name_of = lambda request: request.state\n" + FINDINGS_ASSERT
        )
        function = "<lambda>"
    assert source != ACCEPTED

    [finding] = _guard(source)
    assert finding == (
        f"line {_line_of(source, 'request')}: `request` is not permitted as a parameter of "
        f"`{function}`; {student_guard.RENAME_HINT}"
    )
    assert RENAME in finding


def test_every_reserved_fixture_name_is_rejected_as_a_test_parameter() -> None:
    """`monkeypatch`, `tmp_path`, `pytestconfig`, ... requested by a test are each named."""
    for fixture in sorted(student_guard.RESERVED_PARAMETERS):
        source = ACCEPTED.replace(
            SIGNATURE, f'(harness: InteractionHarness, {fixture}) -> None:\n    """The run leaves'
        )
        assert source != ACCEPTED
        [finding] = _guard(source)
        assert f"`{fixture}` is not permitted as a parameter of" in finding, fixture
    assert _guard(ACCEPTED) == []


def test_the_assertion_may_live_in_a_helper_fed_a_value_from_the_harness() -> None:
    """A helper handed the findings may hold the assert; one handed a literal may not."""
    helper = (
        "\n\ndef clean(found, expected) -> None:\n"
        '    """Assert the scan result."""\n'
        "    assert found == expected\n"
    )
    delegating = (
        HEADER
        + helper
        + REDACTION_TEST.replace(
            FINDINGS_ASSERT,
            '    clean(harness.pii_findings(record.exception_id, note="N-01"), [])\n',
        )
    )
    assert _guard(delegating) == []

    misfed = delegating.replace(
        'clean(harness.pii_findings(record.exception_id, note="N-01"), [])', 'clean([], "x")'
    )
    [finding] = _guard(misfed)
    assert "has no `assert` over a value obtained from the harness" in finding

    # The record may arrive through a helper that returns what the worker returned.
    returned = HEADER + (
        "\n\nasync def _run(harness, note):\n"
        '    """Run one note."""\n'
        '    return await harness.run_worker("valid", note=note)\n'
        "\n\nasync def test_n01(harness: InteractionHarness) -> None:\n"
        '    """A state."""\n'
        '    record = await _run(harness, "N-01")\n'
        "    assert record.state == 'COMPLETED'\n"
    )
    assert _guard(returned) == []


def test_a_value_the_test_built_itself_does_not_count() -> None:
    """A `.state` on something that did not come from the harness is not the stored state."""
    fake = ACCEPTED.replace(
        FINDINGS_ASSERT,
        "    class Fake:\n        state = 'COMPLETED'\n\n    assert Fake().state == 'COMPLETED'\n",
    )
    [finding] = _guard(fake)
    assert finding.startswith("`test_marked_values_reach_nowhere` has no `assert` over a value")

    literal_only = ACCEPTED.replace(
        '    assert redacted == "call [REDACTED:phone]"\n',
        '    assert "[REDACTED:phone]" == "[REDACTED:phone]"\n',
    )
    [finding] = _guard(literal_only)
    assert finding.startswith("`test_the_redactor_output_is_pinned` has no `assert` over a value")


def test_an_assertion_through_a_comprehension_or_over_the_text_counts() -> None:
    """A list built from the trail, or a search of the logs text, carries the harness's origin."""
    through_text = HEADER + (
        "\n\nasync def test_clean(harness: InteractionHarness) -> None:\n"
        '    """No marked value in the logs."""\n'
        '    record = await harness.run_worker("valid", note="N-01")\n'
        "    text = harness.worker_logs(record.exception_id)\n"
        '    assert all(value not in text for value in harness.marked_values(note="N-01"))\n'
    )
    assert _guard(through_text) == []

    unrelated = through_text.replace(
        '    assert all(value not in text for value in harness.marked_values(note="N-01"))\n',
        '    assert all(value for value in harness.marked_values(note="N-01"))\n',
    )
    [finding] = _guard(unrelated)
    assert "has no `assert` over a value obtained from the harness" in finding


def test_methods_of_test_classes_are_collected_and_parametrized_tests_count_once() -> None:
    """`Test*` classes are walked; a parametrized test is one function with one verdict."""
    in_class = HEADER + (
        "\n\nclass TestRedaction:\n"
        '    """Grouped."""\n\n'
        "    async def test_n01(self, harness: InteractionHarness) -> None:\n"
        '        """A constant, not the run."""\n'
        '        await harness.run_worker("valid", note="N-01")\n'
        "        assert True\n"
    )
    [finding] = _guard(in_class)
    assert finding.startswith("`TestRedaction::test_n01` has no `assert` over a value")


def test_source_encoding_is_validated_and_a_syntax_error_is_a_finding() -> None:
    """Bytes are parsed under their declared encoding only when that encoding is UTF-8."""
    with_bom = b"\xef\xbb\xbf" + ACCEPTED.encode("utf-8")
    assert _guard(with_bom) == []
    assert _guard(("# coding: utf-8\n" + ACCEPTED).encode("utf-8")) == []

    [finding] = _guard(("# coding: unicode_escape\n" + ACCEPTED).encode("utf-8"))
    assert finding.startswith(
        "tests/student/test_redaction.py declares the source encoding 'unicode_escape'"
    )
    [finding] = _guard("def (:\n")
    assert finding.startswith("tests/student/test_redaction.py is not valid Python: ")


def test_rules_are_chosen_by_file_name_and_other_files_are_refused(tmp_path: Path) -> None:
    """`findings(path)` applies the rules of the file's name; a foreign name is an error."""
    redaction = tmp_path / "test_redaction.py"
    redaction.write_text(ACCEPTED, encoding="utf-8")

    assert student_guard.findings(redaction) == []
    with pytest.raises(student_guard.StudentGuardError, match="not a student file"):
        student_guard.findings(tmp_path / "test_output_guardrail.py")
    with pytest.raises(student_guard.StudentGuardError, match="not a student file"):
        student_guard.findings(tmp_path / "test_audit.py")
    with pytest.raises(student_guard.StudentGuardError, match="could not be read"):
        student_guard.findings(tmp_path / "missing" / "test_redaction.py")


def test_main_checks_the_file_and_reports_findings_and_unreadable_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 when clean, 1 with findings, 2 when the file cannot be read."""
    redaction = tmp_path / "test_redaction.py"
    redaction.write_text(ACCEPTED, encoding="utf-8")
    assert student_guard.main([str(redaction)]) == 0
    out = capsys.readouterr().out
    assert "tests/student/test_redaction.py uses only the supplied harness" in out

    redaction.write_text(_file_counterexample(), encoding="utf-8")
    assert student_guard.main([str(redaction)]) == 1
    assert "tests/student/test_redaction.py will not be run" in capsys.readouterr().err

    assert student_guard.main([str(tmp_path / "absent" / "test_redaction.py")]) == 2


def test_the_rule_sets_hold_the_reviews_lists() -> None:
    """The names the reviews required are all in the sets, and the import set is the four forms."""
    required_names = {
        "__file__",
        "__import__",
        "__builtins__",
        "importlib",
        "inspect",
        "sys",
        "os",
        "subprocess",
        "builtins",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "compile",
        "open",
        "Path",
        "typing",
        "ForwardRef",
        "get_type_hints",
        "format",
        "format_map",
        # The Task 4.4 harness internals.
        "_request_log",
        "_logs",
        "_notes",
    }
    assert required_names <= student_guard.FORBIDDEN_NAMES
    assert {"format", "format_map", "_request_log", "_logs", "_notes"} <= (
        student_guard.ATTRIBUTE_ONLY_NAMES
    )
    required_parameters = {
        "request",
        "monkeypatch",
        "pytestconfig",
        "capsys",
        "capfd",
        "caplog",
        "tmp_path",
        "tmp_path_factory",
        "recwarn",
    }
    assert required_parameters <= student_guard.RESERVED_PARAMETERS
    assert not required_parameters & student_guard.FORBIDDEN_NAMES
    assert not student_guard.TYPING_NAMES & student_guard.FORBIDDEN_NAMES
    assert student_guard.HARNESS_NAMES == {"InteractionHarness"}
    assert student_guard.HARNESS_MODULE == "tests.security.interaction"
    assert student_guard.PYTEST_CALLS == {"param", "raises"}
    assert student_guard.PERMITTED_MARKS == {"asyncio", "parametrize"}
    assert set(student_guard.STUDENT_FILES) == {"test_redaction.py"}
    assert RULES.path == Path("tests/student/test_redaction.py")
    assert RULES.sources == student_guard.HARNESS_SOURCES
    assert RULES.sources == {
        "run_worker",
        "pii_findings",
        "worker_logs",
        "model_request",
        "expected_summary",
        "audit_trail",
        "audit_text",
        "redact",
    }
    assert RULES.required_attribute is None
    assert not RULES.sources & student_guard.FORBIDDEN_NAMES
    assert not RULES.sources & student_guard.BUILTIN_NAMES
    assert not student_guard.RESERVED_PARAMETERS & student_guard.BUILTIN_NAMES


def _poe_tasks() -> dict[str, object]:
    """Return the layer's Poe task table."""
    tasks = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "poe"
    ]["tasks"]
    assert isinstance(tasks, dict)
    return tasks


def test_verify_runs_the_guard_and_binding_first_and_the_mutations_after_student_tests() -> None:
    """The order the contract documents: snapshot, guard, binding, unit, ... , contract rows, ...

    `poe student-tests` is itself a sequence that runs the guard before the bare pytest run,
    and the two assessed steps go through the assessed-module runner.
    """
    tasks = _poe_tasks()
    verify = tasks["verify"]
    assert isinstance(verify, list)

    assert tasks["student-guard"] == "python -m tests.security.student_guard"
    assert tasks["worker-binding"] == "python -m tests.security.worker_binding"
    assert tasks["redaction-mutation"] == "python -m tests.security.redaction_mutation"
    assert verify.index("student-guard") == verify.index("integrity-record") + 1
    assert verify.index("worker-binding") == verify.index("student-guard") + 1
    assert verify.index("worker-binding") < verify.index("unit")
    assert verify.index("redaction-contract") < verify.index("e2e")
    assert verify.index("student-tests") < verify.index("redaction-tests-contract")
    assert verify.index("redaction-tests-contract") < verify.index("answers")
    assert verify.index("answers") < verify.index("submission")
    assert verify[-1] == "integrity-check"
    assert verify.count("student-guard") == 1
    for retired in ("guardrail-binding", "guardrail-mutation", "output-contract"):
        assert retired not in tasks and retired not in verify
    assert "negative-tests-contract" not in tasks
    assert tasks["student-tests"] == ["student-guard", "student-tests-run"]
    assert tasks["student-tests-run"] == "pytest tests/student"
    assert tasks["e2e"] == ["ingest", "e2e-tests"]
    runner = "python -m tests.security.assessed_run"
    assert tasks["redaction-contract"] == f"{runner} tests/contract/test_redaction_contract.py"
    assert tasks["redaction-tests-contract"] == f"{runner} tests/contract/test_redaction_tests.py"


def test_poe_student_tests_runs_the_guard_before_pytest_collects_a_rejected_file(
    tmp_path: Path,
) -> None:
    """`poe student-tests` must not import a rejected file.

    A student file that writes a marker at import time, and that the guard rejects (it
    imports `pathlib` and reads `__file__`), is placed in a scratch project with the real
    `student-guard`, `student-tests-run`, and `student-tests` task definitions. Through
    `poe student-tests` the guard fails first, the sequence stops, and the marker is never
    written. Through the bare `poe student-tests-run` the same file is imported and the
    marker appears, which is exactly what the guard in front of it prevents.
    """
    tasks = _poe_tasks()
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poe.tasks]\n"
        f'student-guard = "{tasks["student-guard"]}"\n'
        f'student-tests-run = "{tasks["student-tests-run"]}"\n'
        f"student-tests = {json.dumps(tasks['student-tests'])}\n",
        encoding="utf-8",
    )
    security = tmp_path / "tests/security"
    security.mkdir(parents=True)
    shutil.copy(TASK_ROOT / "tests/security/student_guard.py", security / "student_guard.py")
    student = tmp_path / "tests/student"
    student.mkdir()
    marker = student / "imported.marker"
    rejected = student / "test_redaction.py"
    rejected.write_text(
        '"""Rejected: it reads its environment when imported."""\n\n'
        "from pathlib import Path\n\n"
        f'Path(__file__).with_name("{marker.name}").write_text("the module ran", '
        'encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert any("`__file__` is not permitted" in item for item in student_guard.findings(rejected))

    # Poe resolves `python` and `pytest` on PATH; the interpreter running this test and its
    # scripts directory go first, as `uv run` puts the project environment first.
    environment = {
        **os.environ,
        "PATH": os.pathsep.join(
            [
                str(Path(sys.executable).parent),
                sysconfig.get_path("scripts"),
                os.environ.get("PATH", ""),
            ]
        ),
    }

    def poe(task: str) -> str:
        completed = subprocess.run(
            [sys.executable, "-m", "poethepoet", task],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return f"exit {completed.returncode}\n{completed.stdout}{completed.stderr}"

    guarded = poe("student-tests")
    assert not guarded.startswith("exit 0"), guarded
    assert "student-guard: tests/student/test_redaction.py will not be run" in guarded
    assert "`__file__` is not permitted" in guarded
    assert "test session starts" not in guarded, guarded
    assert not marker.exists(), "poe student-tests imported the rejected file"

    bare = poe("student-tests-run")
    assert "test session starts" in bare, bare
    assert marker.read_text(encoding="utf-8") == "the module ran"
