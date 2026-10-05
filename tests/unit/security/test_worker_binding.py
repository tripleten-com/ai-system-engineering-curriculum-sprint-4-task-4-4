"""Coldline.

===================

File:              tests/unit/security/test_worker_binding.py
Component:         Unit tests — Static worker-binding and reach check
Purpose:           Prove the check accepts a worker that imports and calls the supplied redactor
                    and guardrail inside `process`, and rejects every way either name or module
                    could be rebound, a redactor call elsewhere, every spelled path to the test
                    runner, and every import outside the starter's set plus the redactor's.
Interacts With:    tests/security/worker_binding.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Trusted static analysis, verified bindings, a closed reach for application code
Tools:             Python 3.12, pytest

Every test feeds a synthetic fragment to the check; none reads the shipped
`src/worker/use_cases.py`, whose state is the student's (the assessed row reads it). The
fragment is a probe: a class with a `process` that calls each supplied name once, with no
log line, no request and no policy, not the Task's worker. The snippets that spell `exec`,
`_pytest.reports` or `__globals__` are source text handed to the parser; nothing here
executes them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from tests.security import worker_binding as binding

ACCEPTED = '''"""Worker probe."""

from common.redactor import redact
from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, validate_summary


class WorkerApplication:
    """Probe."""

    async def process(self, job, *, delivery_count):
        """Probe: one call of each supplied name, no policy."""
        before = redact(job.reading.handling_note)
        answer = await self._provider.summarize(before)
        after = redact(answer.text)
        return validate_summary(answer.text), after, REVIEW_MESSAGE, RejectedSummary
'''

DOCSTRING = '"""Worker probe."""\n\n'


def _findings(source: str) -> list[str]:
    return binding.findings_for_source(source)


def test_the_permitted_imports_and_direct_calls_pass() -> None:
    """One module-level import of each name, used only as a callee inside process: nothing."""
    assert _findings(ACCEPTED) == []
    repeated = ACCEPTED.replace(
        "        after = redact(answer.text)\n",
        "        after = redact(answer.text)\n        again = redact(after)\n",
    )
    assert _findings(repeated) == []


def test_a_worker_without_either_import_is_named() -> None:
    """The starter's shape (no redactor import) and a worker without the guardrail are named."""
    without_redactor = ACCEPTED.replace("from common.redactor import redact\n", "").replace(
        "redact(", "str("
    )
    [finding] = _findings(without_redactor)
    assert finding == (
        f"the worker does not import `redact` from `common.redactor`; {binding.REDACTOR.hint}"
    )

    without_guardrail = '"""Worker."""\n\nfrom common.redactor import redact\n\n\n'
    without_guardrail += (
        "class WorkerApplication:\n    async def process(self, job, *, delivery_count):\n"
        "        note = redact(job.reading.handling_note)\n"
        "        return await self._provider.summarize(note)\n"
    )
    [finding] = _findings(without_guardrail)
    assert finding.startswith(
        "the worker does not import `validate_summary` from `worker.guardrail`"
    )


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("import common.redactor\n", "`import common.redactor` is not permitted"),
        ("import common\n", "`import common` is not permitted"),
        ("import common.redactor as r\n", "`import common.redactor` is not permitted"),
        ("from common import redactor\n", "`from common import redactor` is not permitted"),
        ("from .redactor import redact\n", "a relative import of `common.redactor`"),
        ("from ..common import redactor\n", "a relative import of `common.redactor`"),
        ("from common.redactor import *\n", "`from common.redactor import *` is not permitted"),
        (
            "from common.redactor import redact as clean\n",
            "`redact as clean` rebinds `redact`",
        ),
        (
            "from common.redactor import placeholder as redact\n",
            "`placeholder as redact` rebinds `redact`",
        ),
        (
            "from mine.scrub import redact\n",
            "`redact` imported from `mine.scrub` is not the supplied `common.redactor`",
        ),
        ("import worker.guardrail\n", "`import worker.guardrail` is not permitted"),
        ("from worker import guardrail\n", "`from worker import guardrail` is not permitted"),
        (
            "from worker.guardrail import validate_summary as check\n",
            "`validate_summary as check` rebinds `validate_summary`",
        ),
    ],
    ids=[
        "import-module",
        "import-package",
        "import-as",
        "from-package",
        "relative",
        "relative-package",
        "star",
        "alias-out",
        "alias-in",
        "other-module",
        "guardrail-import-module",
        "guardrail-from-package",
        "guardrail-alias-out",
    ],
)
def test_every_other_way_to_reach_a_supplied_module_is_a_finding(
    statement: str, expected: str
) -> None:
    """Only `from <module> import <name>` reaches the supplied redactor or guardrail."""
    found = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
    assert any(expected in finding for finding in found), (statement, found)


def test_a_second_import_or_one_inside_a_function_is_a_finding() -> None:
    """Each import is one statement, at module level."""
    twice = ACCEPTED + "\nfrom common.redactor import redact\n"
    assert any("`redact` is imported 2 times" in finding for finding in _findings(twice))

    nested = ACCEPTED.replace(
        "        before = redact(job.reading.handling_note)\n",
        "        from common.redactor import redact\n\n"
        "        before = redact(job.reading.handling_note)\n",
    )
    found = _findings(nested)
    assert any("imported 2 times" in finding for finding in found)
    assert any("must be at module level" in finding for finding in found)


@pytest.mark.parametrize(
    ("snippet", "how"),
    [
        ("def redact(text):\n    return text\n", "a function definition"),
        ("async def redact(text):\n    return text\n", "a function definition"),
        ("class redact:\n    pass\n", "a class definition"),
        ("redact = lambda text: text\n", "an assignment to the name"),
        ("redact: object = None\n", "an assignment to the name"),
        ("(redact := None)\n", "an assignment to the name"),
        ("for redact in ():\n    pass\n", "an assignment to the name"),
        ("del redact\n", "an assignment to the name"),
        ("def helper(redact):\n    return redact\n", "a parameter"),
        ("helper = lambda redact: redact\n", "a parameter"),
        ("try:\n    pass\nexcept Exception as redact:\n    pass\n", "an exception handler"),
        ("def helper():\n    global redact\n", "a global or nonlocal statement"),
        ("match 1:\n    case redact:\n        pass\n", "a match capture"),
        ("redactor.redact = None\n", "an attribute assignment"),
        ("def validate_summary(raw):\n    return raw\n", "a function definition"),
        ("validate_summary = lambda raw: raw\n", "an assignment to the name"),
    ],
    ids=[
        "def",
        "async-def",
        "class",
        "assign",
        "annotated",
        "walrus",
        "for",
        "del",
        "parameter",
        "lambda",
        "handler",
        "global",
        "match",
        "attribute",
        "guardrail-def",
        "guardrail-assign",
    ],
)
def test_every_rebinding_of_a_supplied_name_is_named_by_how(snippet: str, how: str) -> None:
    """A definition, an assignment target, a parameter, a handler, a capture: each is a finding."""
    name = "validate_summary" if "validate_summary" in snippet else "redact"
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any(f"{how} rebinds `{name}`" in finding for finding in found), (snippet, found)


def test_handing_a_supplied_function_to_another_name_is_a_finding() -> None:
    """`clean = redact` lets a call through `clean` escape the mutation."""
    aliased = ACCEPTED + "\nclean = redact\n"
    found = _findings(aliased)
    assert any("`redact` is used other than as the callee of a call" in f for f in found), found
    passed = ACCEPTED + "\nresult = list(map(redact, ['x']))\n"
    assert any("used other than as the callee" in finding for finding in _findings(passed))
    guardrail = ACCEPTED + "\ncheck = validate_summary\n"
    assert any("`validate_summary` is used other than" in f for f in _findings(guardrail))


@pytest.mark.parametrize(
    "snippet",
    [
        "import sys\nsys.modules['common.redactor'] = None\n",
        "import importlib\nimportlib.reload(redact)\n",
        "setattr(redact, 'x', 1)\n",
        "globals()['redact'] = None\n",
        "exec('redact = None')\n",
        "__import__('common.redactor')\n",
    ],
    ids=["sys-modules", "importlib", "setattr", "globals", "exec", "dunder-import"],
)
def test_runtime_rebinding_doors_are_findings(snippet: str) -> None:
    """The names that rebind a module or a global at runtime have no place in the worker."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any(
        "can rebind a module or a global at runtime" in finding
        or "is not permitted in application code" in finding
        for finding in found
    ), (snippet, found)


def test_a_redactor_call_outside_process_is_named_and_one_inside_is_not() -> None:
    """Rule 5: `redact(...)` at module level, in a helper, or in another method is a finding."""
    module_level = ACCEPTED + "\nCLEAN = redact('x')\n"
    [finding] = _findings(module_level)
    line = module_level.count(chr(10))
    assert finding.startswith(f"line {line}: `redact(...)` is called outside")
    assert "inside `WorkerApplication.process`" in finding

    helper = ACCEPTED + "\n\ndef scrub(text):\n    return redact(text)\n"
    found = _findings(helper)
    assert any("called outside `WorkerApplication.process`" in f for f in found)

    other_method = ACCEPTED.replace(
        '    """Probe."""\n',
        '    """Probe."""\n\n    def prepare(self, text):\n        return redact(text)\n',
    )
    found = _findings(other_method)
    assert any("called outside `WorkerApplication.process`" in f for f in found)

    nested_in_process = ACCEPTED.replace(
        "        after = redact(answer.text)\n",
        "        after = [redact(part) for part in (answer.text,)][0]\n",
    )
    assert _findings(nested_in_process) == []

    no_class = (
        '"""Worker."""\n\nfrom common.redactor import redact\n'
        "from worker.guardrail import validate_summary\n\n\n"
        "async def process(job):\n    return validate_summary(redact(job))\n"
    )
    found = _findings(no_class)
    assert any("called outside `WorkerApplication.process`" in f for f in found)


# --- Rule 5b: no redaction after the guardrail call --------------------------------------

# The review's shape: the raw answer is validated, then the validated summary is redacted
# and stored, so the guardrail checked one string and the record holds another.
VERDICT_REDACTING_TAIL = (
    "        verdict = validate_summary(answer.text)\n"
    "        clean = redact(verdict.summary)\n"
    "        return clean, REVIEW_MESSAGE, RejectedSummary\n"
)
ACCEPTED_RETURN = (
    "        after = redact(answer.text)\n"
    "        return validate_summary(answer.text), after, REVIEW_MESSAGE, RejectedSummary\n"
)


def test_a_redaction_of_the_validated_summary_is_named_by_the_order_rule() -> None:
    """`redact(verdict.summary)` after `validate_summary(answer.text)` is a finding."""
    worker = ACCEPTED.replace(ACCEPTED_RETURN, VERDICT_REDACTING_TAIL)
    found = _findings(worker)
    assert len(found) == 1, found
    [finding] = found
    assert "`redact(...)` is called after `validate_summary`" in finding
    assert "never redact the validated summary" in finding
    line = worker.splitlines().index("        clean = redact(verdict.summary)") + 1
    assert finding.startswith(f"line {line}: ")

    # Anything derived from the verdict, redacted after the call, is the same finding.
    derived = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        verdict = validate_summary(answer.text)\n"
        "        text = verdict.summary\n"
        "        return redact(f'{text}'), REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert any("called after `validate_summary`" in item for item in _findings(derived))

    # On one line, after the guardrail call's end, is after it too.
    same_line = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        verdict = validate_summary(answer.text); clean = redact(verdict.summary)\n"
        "        return clean, REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert any("called after `validate_summary`" in item for item in _findings(same_line))


def test_a_redaction_before_or_inside_the_guardrail_call_is_not_a_finding() -> None:
    """The lesson's shapes pass: redacted first and handed over, or redacted in the argument."""
    before = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        redacted_answer = redact(answer.text)\n"
        "        verdict = validate_summary(redacted_answer)\n"
        "        return verdict, REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert _findings(before) == []

    inside = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        verdict = validate_summary(redact(answer.text))\n"
        "        return verdict, REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert _findings(inside) == []

    spread = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        verdict = validate_summary(\n            redact(answer.text),\n        )\n"
        "        return verdict, REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert _findings(spread) == []


def test_the_variant_shape_without_an_answer_side_call_passes_the_static_rules() -> None:
    """A worker that redacts the note and hands the raw answer over is the pii-echo row's.

    The static rules say nothing about an absent answer-side call (the registered
    negative must still reach exactly `test_pii_echo_run_completes_redacted_with_its_
    contact_in_no_location`), and the observation accepts the raw hand-over for it.
    """
    variant_shape = ACCEPTED.replace(
        ACCEPTED_RETURN,
        "        return validate_summary(answer.text), REVIEW_MESSAGE, RejectedSummary\n",
    )
    assert _findings(variant_shape) == []
    assert binding.answer_side_calls(ast.parse(variant_shape)) == []


def test_answer_side_calls_are_the_redact_calls_after_the_provider_call() -> None:
    """The observation reads the answer side the way the mutation runner does."""
    tree = ast.parse(ACCEPTED)
    calls = binding.answer_side_calls(tree)
    assert [ast.unparse(call) for call in calls] == ["redact(answer.text)"]

    verdict_redacting = ast.parse(ACCEPTED.replace(ACCEPTED_RETURN, VERDICT_REDACTING_TAIL))
    assert [ast.unparse(call) for call in binding.answer_side_calls(verdict_redacting)] == [
        "redact(verdict.summary)"
    ]

    assert binding.answer_side_calls(ast.parse("x = 1\n")) == []
    no_provider = ACCEPTED.replace(
        "        answer = await self._provider.summarize(before)\n", "        answer = before\n"
    )
    assert binding.answer_side_calls(ast.parse(no_provider)) == []
    assert binding.order_findings(ast.parse("class WorkerApplication:\n    pass\n")) == []


PROVIDER_LINE = "        answer = await self._provider.summarize(before)\n"
# The third review's shape: the provider call, then a lambda holding the call, on one line.
LAMBDA_PROVIDER_LINE = (
    "        answer = await self._provider.summarize(before); clean = lambda text: redact(text)\n"
)


def _sides(source: str) -> list[tuple[str, str]]:
    """Return each `redact(...)` call of a worker's `process` with the side the classifier gives."""
    process = binding.process_method(ast.parse(source))
    assert process is not None
    provider = binding.provider_call(process)
    assert provider is not None
    return [
        (ast.unparse(call), binding.call_side(call, provider))
        for call in binding._redact_calls(process)
    ]


def test_the_call_side_classifier_reads_the_provider_line_by_position_not_by_line() -> None:
    """A call on the provider call's line is on the side its position says, for every reader.

    After the provider call ends, on the same line, is the answer side (the third
    review's `; clean = lambda text: redact(text)`); before it on that line, or inside
    its argument list on that line or a later one, is the note side. `answer_side_calls`
    and the mutation runner read the same classifier.
    """
    assert _sides(ACCEPTED) == [
        ("redact(job.reading.handling_note)", "note"),
        ("redact(answer.text)", "answer"),
    ]

    after = ACCEPTED.replace(
        PROVIDER_LINE,
        "        answer = await self._provider.summarize(before); echo = redact(answer.text)\n",
    )
    assert dict(_sides(after)) == {
        "redact(job.reading.handling_note)": "note",
        "redact(answer.text)": "answer",
    }
    assert [ast.unparse(c) for c in binding.answer_side_calls(ast.parse(after))] == [
        "redact(answer.text)",
        "redact(answer.text)",
    ]

    ahead = ACCEPTED.replace(
        PROVIDER_LINE,
        "        again = redact(before); answer = await self._provider.summarize(again)\n",
    )
    assert dict(_sides(ahead))["redact(before)"] == "note"

    inside = ACCEPTED.replace(
        PROVIDER_LINE, "        answer = await self._provider.summarize(redact(before))\n"
    )
    assert dict(_sides(inside))["redact(before)"] == "note"

    spread = ACCEPTED.replace(
        PROVIDER_LINE,
        "        answer = await self._provider.summarize(\n"
        "            redact(before),\n"
        "        )\n",
    )
    assert dict(_sides(spread))["redact(before)"] == "note"
    assert [ast.unparse(c) for c in binding.answer_side_calls(ast.parse(spread))] == [
        "redact(answer.text)"
    ]


# --- Rule 5c: no deferred redaction --------------------------------------------------------


def test_the_deferred_lambda_beside_the_provider_call_is_named_and_is_answer_side() -> None:
    """The third review's worker: a lambda holding the call, applied after the guardrail.

    `answer = await ...summarize(request); clean = lambda text: redact(text)` spells the
    call before `validate_summary`, so the order rule is silent, inside `process`, so the
    placement rule is silent, and as a callee, so rule 3 is silent; `clean(verdict.summary)`
    then redacts the validated summary at run time. Rule 5c names the call by its lambda,
    and the classifier puts it on the answer side, so the observation requires the
    redacted hand-over and the answer mutation strips it.
    """
    worker = ACCEPTED.replace(PROVIDER_LINE, LAMBDA_PROVIDER_LINE).replace(
        ACCEPTED_RETURN,
        "        verdict = validate_summary(answer.text)\n"
        "        return clean(verdict.summary), REVIEW_MESSAGE, RejectedSummary\n",
    )
    found = _findings(worker)
    assert len(found) == 1, found
    [finding] = found
    line = worker.splitlines().index(LAMBDA_PROVIDER_LINE.rstrip("\n")) + 1
    assert finding.startswith(f"line {line}: `redact(...)` is called inside a lambda in ")
    assert "`WorkerApplication.process`, so the redaction is deferred" in finding
    assert binding.DEFERRED_HINT in finding
    assert [ast.unparse(c) for c in binding.answer_side_calls(ast.parse(worker))] == [
        "redact(text)"
    ]


def test_a_redaction_inside_a_nested_function_in_process_is_named() -> None:
    """A `def` inside `process` that calls `redact` is the same deferral with a name."""
    worker = ACCEPTED.replace(
        "        after = redact(answer.text)\n",
        "        def clean(text):\n            return redact(text)\n\n"
        "        after = clean(answer.text)\n",
    )
    found = _findings(worker)
    assert len(found) == 1, found
    assert "called inside the nested function `clean` in `WorkerApplication.process`" in found[0]

    async_nested = ACCEPTED.replace(
        "        after = redact(answer.text)\n",
        "        async def clean(text):\n            return redact(text)\n\n"
        "        after = await clean(answer.text)\n",
    )
    assert any("nested function `clean`" in item for item in _findings(async_nested))

    # A comprehension runs where it is written: not a deferral (the placement test's shape).
    comprehension = ACCEPTED.replace(
        "        after = redact(answer.text)\n",
        "        after = [redact(part) for part in (answer.text,)][0]\n",
    )
    assert _findings(comprehension) == []
    # A lambda or a nested function elsewhere in the file is rule 5's finding, not 5c's.
    elsewhere = ACCEPTED + "\nclean = lambda text: redact(text)\n"
    found = _findings(elsewhere)
    assert any("called outside `WorkerApplication.process`" in item for item in found)
    assert not any("deferred" in item for item in found)


@pytest.mark.parametrize(
    "snippet",
    [
        "        clean = redact\n",
        "        parts = list(map(redact, (answer.text,)))\n",
        "        return redact\n",
        "        clean = lambda: redact\n",
        "        clean = redact if delivery_count else str\n",
    ],
    ids=["assigned", "passed", "returned", "lambda-body", "conditional"],
)
def test_redact_as_a_value_inside_process_is_a_finding(snippet: str) -> None:
    """Inside `process` as elsewhere, `redact` is the callee of a call or it is a finding."""
    worker = ACCEPTED.replace("        after = redact(answer.text)\n", snippet)
    found = _findings(worker)
    assert any("`redact` is used other than as the callee of a call" in item for item in found), (
        snippet,
        found,
    )


# --- The reach rules -------------------------------------------------------------------------

RUNNER_IMPORTS = [
    "import pytest\n",
    "import _pytest\n",
    "import _pytest.reports\n",
    "from _pytest.reports import TestReport\n",
    "import sys\n",
    "from sys import modules\n",
    "import importlib\n",
    "import importlib.util\n",
    "from importlib import import_module\n",
    "import builtins\n",
    "import gc\n",
    "import inspect\n",
    "import ctypes\n",
    "import ctypes.util as cu\n",
    "import types\n",
    "from types import ModuleType\n",
    "import runpy\n",
    "import unittest\n",
    "import unittest.mock\n",
    "import unittest.mock as m\n",
    "from unittest.mock import patch\n",
    "from unittest import mock\n",
    "import mock\n",
    "from mock import patch\n",
]


@pytest.mark.parametrize("statement", RUNNER_IMPORTS, ids=[s.strip() for s in RUNNER_IMPORTS])
def test_an_import_of_a_runner_module_is_a_finding(statement: str) -> None:
    """`pytest`, `_pytest`, `sys`, `importlib`, ... and their submodules are refused as imports."""
    found = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
    assert any(
        "is not permitted in application code" in item and "test runner" in item for item in found
    ), (statement, found)


def test_unittest_and_mock_are_runner_modules() -> None:
    """`unittest` (for `unittest.mock`) and `mock` are in the refused set, by top-level name."""
    assert {"unittest", "mock"} <= binding.RUNNER_MODULES
    found = _findings(ACCEPTED + "\nimport logging\nPATCH = logging.mock\n")
    assert any("the same door" in item for item in found), found


def test_a_module_whose_name_merely_ends_like_a_runner_module_is_not_a_reach_finding() -> None:
    """`starlette.types` is not `types`; `api.security.tokens` is not `sys`.

    The reach rule matches the top-level name, so neither is a path to the runner; both
    are outside the import allowlist, which names them for that reason alone. A permitted
    import of a permitted name is nothing.
    """
    lookalikes = (
        "from starlette.types import Lifespan\n",
        "from api.security.tokens import Principal\n",
    )
    for statement in lookalikes:
        found = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
        assert not any("test runner" in item for item in found), (statement, found)
        assert [item for item in found if "import allowlist" in item], (statement, found)
    worker = ACCEPTED.replace(DOCSTRING, DOCSTRING + "from common.audit import AuditEvent\n")
    assert _findings(worker) == []


# --- Rule 9: the import allowlist ------------------------------------------------------------

STARTER_IMPORTS = {
    "logging": None,
    "collections.abc": {"Callable"},
    "datetime": {"datetime"},
    "enum": {"StrEnum"},
    "typing": {"Protocol"},
    "common.audit": {"AuditEvent", "AuditRecorder", "answer_digest"},
    "domain.contracts": {"ExceptionJob", "ExceptionState", "ModelRequest", "SensorReading"},
    "domain.errors": {"TerminalProviderError"},
    "domain.failures": {"RetrievalUnavailable"},
    "domain.repositories": {"ExceptionRepository"},
    "ports": {"ModelProvider"},
    "worker.guardrail": {"REVIEW_MESSAGE", "RejectedSummary", "validate_summary"},
    "worker.procedures": {"ProcedureExcerpt"},
}


def test_the_import_allowlist_is_the_starters_imports_plus_the_redactor() -> None:
    """The pinned statements are the starter's thirteen imports plus the redactor's.

    Pinned here as the modules and names the rule applies, so a change to the constant is
    a deliberate change to this test too; the shipped worker is not read (its state is the
    student's). No permitted module is a runner module, and no statement carries an alias.
    """
    assert len(binding.PERMITTED_IMPORTS) == len(STARTER_IMPORTS) + 1
    assert "from common.redactor import redact" in binding.PERMITTED_IMPORTS
    plain = {module for module, names in STARTER_IMPORTS.items() if names is None}
    assert binding.PERMITTED_MODULES == plain
    expected_names = {module: names for module, names in STARTER_IMPORTS.items() if names}
    expected_names["common.redactor"] = {"redact"}
    permitted_names = {module: set(names) for module, names in binding.PERMITTED_NAMES.items()}
    assert permitted_names == expected_names
    assert not any(
        binding._top_module(module) in binding.RUNNER_MODULES
        for module in (*binding.PERMITTED_MODULES, *binding.PERMITTED_NAMES)
    )
    assert not any(" as " in item or "*" in item for item in binding.PERMITTED_IMPORTS)
    # A file of exactly the permitted imports trips no rule of this module.
    assert _findings(DOCSTRING + "\n".join(binding.PERMITTED_IMPORTS) + "\n") == []


def test_a_malformed_permitted_imports_tuple_is_refused_at_import() -> None:
    """A statement with an alias, a `*`, or no import at all is a programming error here."""
    for bad in ("import logging as log", "from enum import *", "x = 1", "from . import y"):
        with pytest.raises(ValueError, match="PERMITTED_IMPORTS"):
            binding._permitted_imports((bad,))


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        ("from operator import attrgetter\n", "`from operator import attrgetter` is not in"),
        ("import json\n", "`import json` is not in"),
        ("import logging.handlers\n", "`import logging.handlers` is not in"),
        ("import logging as log\n", "`import logging as log` aliases `logging`"),
        ("from datetime import datetime as dt\n", "aliases `datetime`"),
        ("from common.audit import AuditEvent as Event\n", "aliases `AuditEvent`"),
        ("from worker.guardrail import ValidatedSummary\n", "imports `ValidatedSummary`, which"),
        ("from common.redactor import placeholder\n", "imports `placeholder`, which is not"),
        ("from __future__ import annotations\n", "`from __future__ import annotations` is not"),
        ("from . import helpers\n", "is a relative import, which is not in"),
        ("from .guardrail import REVIEW_MESSAGE\n", "is a relative import, which is not in"),
        ("from common.audit import *\n", "imports every name, which is not permitted by"),
    ],
    ids=[
        "operator",
        "json",
        "submodule",
        "module-alias",
        "name-alias",
        "supplied-name-alias",
        "other-guardrail-name",
        "other-redactor-name",
        "future",
        "relative",
        "relative-guardrail",
        "star",
    ],
)
def test_an_import_outside_the_allowlist_is_a_finding(statement: str, expected: str) -> None:
    """A new module, a new name from a permitted module, a relative import, a `*` or an alias."""
    found = _findings(ACCEPTED.replace(DOCSTRING, DOCSTRING + statement))
    matching = [item for item in found if expected in item]
    assert matching, (statement, found)
    assert all(binding.ALLOWLIST_HINT in item for item in matching)
    assert all(item.startswith("line 3: ") for item in matching), matching


def test_the_review_s_attrgetter_reach_is_named_by_the_allowlist() -> None:
    """`attrgetter("sys.modules")(logging)` spells no runner name; its import is the finding.

    The second review's counterexample: a permitted module (`logging`) is walked to
    `sys.modules` by a string handed to `operator.attrgetter`, so no reach rule sees a
    runner module, a dynamic name or a dunder attribute. The import of `operator` is
    outside the allowlist, which is the one finding, before anything of the file runs.
    """
    worker = ACCEPTED.replace(
        DOCSTRING, DOCSTRING + "import logging\nfrom operator import attrgetter\n"
    ) + (
        '\nreports = attrgetter("sys.modules")(logging).get("_pytest.reports")\n'
        "if reports is not None:\n"
        "    reports.TestReport.from_item_and_call = lambda item, call: None\n"
    )
    found = _findings(worker)
    assert len(found) == 1, found
    assert "`from operator import attrgetter` is not in the worker's import allowlist" in found[0]
    # Spelled through `getattr` instead, the dynamic name is the finding.
    by_getattr = ACCEPTED.replace(DOCSTRING, DOCSTRING + "import logging\n") + (
        '\nreports = getattr(logging, "sys").modules.get("_pytest.reports")\n'
    )
    found = _findings(by_getattr)
    assert any("`getattr` is not permitted in application code" in item for item in found), found
    assert any("the same door" in item for item in found), found


@pytest.mark.parametrize(
    ("snippet", "name"),
    [
        ("exec('x = 1')\n", "exec"),
        ("eval('1')\n", "eval"),
        ("code = compile('x = 1', '<s>', 'exec')\n", "compile"),
        ("__import__('_pytest')\n", "__import__"),
        ("globals()['x'] = 1\n", "globals"),
        ("setattr(WorkerApplication, 'x', 1)\n", "setattr"),
        ("delattr(WorkerApplication, 'process')\n", "delattr"),
        ("run = exec\n", "exec"),
        ("table = __builtins__\n", "__builtins__"),
        ("import logging\nSYS = getattr(logging, 'sys')\n", "getattr"),
        ("import logging\nTABLE = vars(logging)\n", "vars"),
        ("SCOPE = locals()\n", "locals"),
        ("import logging\nNAMES = dir(logging)\n", "dir"),
        ("read = getattr\n", "getattr"),
    ],
    ids=[
        "exec",
        "eval",
        "compile",
        "import",
        "globals",
        "setattr",
        "delattr",
        "alias",
        "builtins",
        "getattr",
        "vars",
        "locals",
        "dir",
        "getattr-alias",
    ],
)
def test_a_dynamic_name_is_a_finding_called_or_handed_on(snippet: str, name: str) -> None:
    """The names that run text as code, rebind at runtime, or reach a namespace by a string."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any(f"`{name}` is not permitted in application code" in item for item in found), (
        snippet,
        found,
    )


def test_the_three_argument_type_call_is_a_finding_and_the_one_argument_form_is_not() -> None:
    """`type(name, bases, namespace)` builds a class at runtime; `type(x)` is an ordinary call."""
    building = ACCEPTED + "\nPatched = type('Patched', (), {'outcome': 'passed'})\n"
    found = _findings(building)
    assert any("`type(...)` with three arguments is not permitted" in item for item in found), found

    starred = ACCEPTED + "\nPatched = type(*PARTS)\n"
    assert any("`type(...)` with three arguments" in item for item in _findings(starred))

    asking = ACCEPTED + "\nKIND = type(REVIEW_MESSAGE)\nif type(KIND) is type:\n    pass\n"
    assert _findings(asking) == []


@pytest.mark.parametrize(
    "snippet",
    [
        "TABLE = WorkerApplication.__dict__\n",
        "SCOPE = WorkerApplication.process.__globals__\n",
        "CODE = WorkerApplication.process.__code__\n",
        "BUILTINS = WorkerApplication.process.__builtins__\n",
        "KIND = WorkerApplication().__class__\n",
        "MODULE = WorkerApplication.__module__\n",
        "WorkerApplication.__wrapped__ = None\n",
    ],
    ids=["dict", "globals", "code", "builtins", "class", "module", "wrapped"],
)
def test_a_dunder_attribute_is_a_finding(snippet: str) -> None:
    """The five named doors, and every other dunder attribute, are refused."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any("a dunder attribute reaches" in item for item in found), (snippet, found)


@pytest.mark.parametrize(
    "snippet",
    [
        "from logging import sys as runtime\n",
        "import logging\nTABLE = logging.sys.modules\n",
        "from os import sys\n",
        "import logging\nKIND = logging.types\n",
    ],
    ids=["from-alias", "attribute-chain", "from-os", "attribute-types"],
)
def test_a_runner_module_reached_through_another_module_is_a_finding(snippet: str) -> None:
    """`logging.sys` is the same door as `import sys`, by import or by attribute."""
    found = _findings(ACCEPTED + "\n" + snippet)
    assert any("the same door" in item for item in found), (snippet, found)


FRAME_NAMES = [
    "currentframe",
    "_getframe",
    "f_builtins",
    "f_globals",
    "f_locals",
    "f_back",
    "f_code",
    "tb_frame",
    "gi_frame",
    "cr_frame",
    "ag_frame",
]


@pytest.mark.parametrize("name", FRAME_NAMES)
def test_a_frame_name_is_a_finding_as_an_attribute_and_as_a_name(name: str) -> None:
    """`logging.currentframe`, `x.f_builtins`, `tb.tb_frame`, ... reach the interpreter's state."""
    assert name in binding.FRAME_NAMES
    attribute = ACCEPTED + f"\nimport logging\nFRAME = logging.{name}\n"
    found = _findings(attribute)
    assert any(
        f"`logging.{name}` is not permitted in application code" in item and "frame" in item
        for item in found
    ), (name, found)
    bare = ACCEPTED + f"\nFRAME = {name}\n"
    found = _findings(bare)
    assert any(f"`{name}` is not permitted in application code" in item for item in found), found


def test_frame_access_through_a_permitted_module_is_named_before_it_could_run() -> None:
    """The third review's attack: a frame's builtins table reaches `__import__` by a string.

    `logging.currentframe().f_builtins["__import__"]("_pytest.reports", ...)` imports
    `logging` (permitted), spells no runner module, no dynamic name (`"__import__"` is a
    string constant, not a name) and no dunder attribute, and the `ModuleNotFoundError`
    handler lets the same file run inside the worker container. The two frame names are
    the findings, before anything of the file runs.
    """
    worker = ACCEPTED.replace(DOCSTRING, DOCSTRING + "import logging\n") + (
        "\ntry:\n"
        '    reports = logging.currentframe().f_builtins["__import__"](\n'
        '        "_pytest.reports", fromlist=["TestReport"]\n'
        "    )\n"
        "except ModuleNotFoundError:\n"
        "    reports = None\n"
        "else:\n"
        "    reports.TestReport.from_item_and_call = lambda item, call: None\n"
    )
    found = _findings(worker)
    assert len(found) == 2, found
    assert any("`logging.currentframe` is not permitted in application code" in i for i in found)
    assert any(
        "`logging.currentframe().f_builtins` is not permitted in application code" in item
        for item in found
    )
    assert all("frame" in item and binding.REACH_HINT in item for item in found)


def test_a_report_patch_through_the_runner_is_named_before_it_could_run() -> None:
    """The review's attack: rewrite `TestReport.from_item_and_call` so failures report as passed."""
    direct = ACCEPTED + (
        "\nfrom _pytest.reports import TestReport\n\n"
        "def _passed(item, call):\n    report = _original(item, call)\n"
        "    report.outcome = 'passed'\n    return report\n\n"
        "_original = TestReport.from_item_and_call\n"
        "TestReport.from_item_and_call = staticmethod(_passed)\n"
    )
    found = _findings(direct)
    assert any("`from _pytest.reports import TestReport`" in item for item in found), found

    through_modules = ACCEPTED + (
        "\nimport sys\n\nreports = sys.modules['_pytest.reports']\n"
        "reports.TestReport.from_item_and_call = lambda item, call: None\n"
    )
    found = _findings(through_modules)
    assert any("`import sys`" in item for item in found), found

    through_globals = ACCEPTED + "\nreports = WorkerApplication.process.__globals__['_pytest']\n"
    found = _findings(through_globals)
    assert any("__globals__" in item for item in found), found

    # The second review's attack: `unittest.mock.patch` names the runner's report class by
    # a string, so no `_pytest` import, dynamic name or dunder attribute is spelled; the
    # `ModuleNotFoundError` handler lets the same file run inside the worker container.
    through_patch = ACCEPTED + (
        "\nfrom unittest.mock import patch\n\n"
        "try:\n    _patcher = patch('_pytest.reports.TestReport.from_item_and_call')\n"
        "    _original = _patcher.getter()\n"
        "except ModuleNotFoundError:\n    _patcher = None\n"
    )
    found = _findings(through_patch)
    assert any("`from unittest.mock import patch`" in item for item in found), found

    aliased_patch = ACCEPTED + (
        "\nimport unittest.mock as m\n\n"
        "m.patch('_pytest.reports.TestReport.from_item_and_call').start()\n"
    )
    found = _findings(aliased_patch)
    assert any("`import unittest.mock`" in item for item in found), found


def test_only_the_worker_file_is_checked_and_the_process_method_is_found() -> None:
    """`use_cases.py` gets the rules; another file is an error; the `process` method is found."""
    assert binding.findings_for_source(ACCEPTED, Path("elsewhere/use_cases.py")) == []
    with pytest.raises(binding.WorkerBindingError, match="not the worker file"):
        binding.findings_for_source(ACCEPTED, Path("src/api/routes.py"))

    assert binding.process_method(ast.parse(ACCEPTED)) is not None
    assert binding.process_method(ast.parse("x = 1\n")) is None
    assert binding.process_method(ast.parse("class WorkerApplication:\n    pass\n")) is None


def test_findings_are_deduplicated_and_a_syntax_error_is_a_finding() -> None:
    """One finding per distinct problem; an unparsable file is reported as such."""
    found = _findings(ACCEPTED + "\nclean = redact\nclean = redact\n")
    assert len(found) == len(set(found))
    [finding] = _findings("def (:\n")
    assert finding.startswith("src/worker/use_cases.py is not valid Python: ")


def test_application_findings_cover_the_worker_under_a_root(tmp_path: Path) -> None:
    """The worker is read from the root and each finding carries its file's path."""
    (tmp_path / "src/worker").mkdir(parents=True)
    (tmp_path / "src/worker/use_cases.py").write_text(ACCEPTED, encoding="utf-8")
    assert binding.application_findings(tmp_path) == []

    (tmp_path / "src/worker/use_cases.py").write_text(
        ACCEPTED + "\nclean = redact\nimport gc\n", encoding="utf-8"
    )
    found = binding.application_findings(tmp_path)
    # The handed-on name, the runner import (rule 6) and the same import outside the
    # allowlist (rule 9): three findings, each with the file's path.
    assert len(found) == 3, found
    assert all(item.startswith("src/worker/use_cases.py: ") for item in found)
    assert any("used other than as the callee" in item for item in found)
    assert any("`import gc` is not permitted in application code" in item for item in found)
    assert any("`import gc` is not in the worker's import allowlist" in item for item in found)

    (tmp_path / "src/worker/use_cases.py").unlink()
    with pytest.raises(binding.WorkerBindingError, match="could not be read"):
        binding.application_findings(tmp_path)


def test_findings_read_the_file_and_main_reports_the_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`findings(path)` reads bytes; `main` exits 0 clean, 1 with findings, 2 unreadable."""
    worker = tmp_path / "use_cases.py"
    worker.write_text(ACCEPTED, encoding="utf-8")
    assert binding.findings(worker) == []
    assert binding.main([str(worker)]) == 0
    out = capsys.readouterr().out
    assert "imports `redact` from `common.redactor`" in out
    assert "`validate_summary` from `worker.guardrail`" in out

    worker.write_text(ACCEPTED + "\nclean = redact\nimport inspect\n", encoding="utf-8")
    assert binding.main([str(worker)]) == 1
    captured = capsys.readouterr()
    assert "does not bind the supplied redactor and guardrail" in captured.err
    assert "used other than as the callee of a call" in captured.err
    assert "`import inspect`" in captured.err

    with pytest.raises(binding.WorkerBindingError, match="could not be read"):
        binding.findings(tmp_path / "absent" / "use_cases.py")
    assert binding.main([str(tmp_path / "absent" / "use_cases.py")]) == 2
    assert binding.main([str(tmp_path / "routes.py")]) == 2
