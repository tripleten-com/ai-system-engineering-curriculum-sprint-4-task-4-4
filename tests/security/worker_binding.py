"""Coldline.

===================

File:              tests/security/worker_binding.py
Component:         Security tooling — Static worker-binding and reach check
Purpose:           Check, without importing it, that src/worker/use_cases.py binds the supplied
                    redactor and the supplied guardrail by the names it imports, rebinds neither,
                    calls the redactor only inside `WorkerApplication.process`, imports nothing
                    beyond the starter's imports and the redactor's, and cannot reach the test
                    runner, the interpreter, or another module's bindings.
Interacts With:    src/worker/use_cases.py, src/common/redactor.py, src/worker/guardrail.py,
                    tests/security/guardrail_observation.py, tests/security/redaction_mutation.py,
                    tests/contract/test_redaction_tests.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Trusted static analysis, verified bindings, mutation targets, a closed reach
                    for application code
Tools:             Python 3.12, ast

The two redaction mutations replace calls spelled ``redact(...)`` in the worker with the
text they were handed. That proves something only when the name is the supplied
redactor: a worker that defined its own ``redact``, or rebound the name or the
``common.redactor`` module, would pass a scan of its own making and never run the
supplied rules. The same holds for ``validate_summary``, which Task 4.3 bound and this
Task keeps. This check reads the worker as bytes, parses it, and requires, for each of the
two supplied names:

1. one ``from <module> import ...`` statement at module level that imports the name under
   its own name (no ``as``), and no other import of the module in any form (``import
   common.redactor``, ``import common``, a relative import, ``from common import
   redactor``);
2. no other binding of the name: not a ``def``, a class, an assignment target (plain,
   annotated, augmented, walrus, ``for``, ``with``, ``except ... as``, a match capture,
   ``global`` or ``nonlocal``), a parameter, a lambda parameter, or a second import;
3. every other appearance of the name is the callee of a call: handing the function to
   another name (``clean = redact``) would let a call through that name escape the
   mutation;
4. no attribute assignment on the module, no ``sys.modules``, and none of the names that
   rebind a module or a global at runtime (``importlib``, ``sys``, ``builtins``).

Two rules are the redactor's alone:

5. every ``redact(...)`` call is inside ``WorkerApplication.process``. The lesson places
   both redaction calls there (the note where it is first read, the answer before the
   guardrail), and the mutations tell the two calls apart by their position in ``process``
   relative to the provider call; a call elsewhere has no side.
5b. no ``redact(...)`` call comes after the ``validate_summary(...)`` call in ``process``
   (a call that is the guardrail call's own argument is before it). The answer is
   redacted before the guardrail checks it, so the schema sees the text that will be
   stored; a worker that validates the raw answer and then redacts ``verdict.summary``,
   or anything derived from it, has the guardrail check one string and stores another.
   An absent answer-side call is not this rule's business: the pii-echo row names it.
5c. inside ``process``, ``redact`` appears only as the direct callee of a call that runs
   where it is written: no ``redact(...)`` call inside a lambda or a nested function. Such
   a call runs when the lambda or the function is called, not where it is spelled, so its
   position says nothing about its side, and ``clean = lambda text: redact(text)`` beside
   the provider call, applied to ``verdict.summary`` after the guardrail, is rule 5b's
   worker in another spelling. ``redact`` as a value (``clean = redact``, passed on,
   returned, or the body of a lambda without a call) is rule 3's finding already.

A ``redact(...)`` call's **side** is its position relative to the provider call
(``self._provider.summarize(...)``), decided by one classifier, ``call_side``, that this
module and the two mutations share: a call that starts after the provider call ends is on
the answer side; any other call, one before it, one inside its argument list, or one on
its line ahead of it, is on the note side. A call on the provider call's own line is
therefore classified the same way wherever it is read.

The assessed checks import the worker into the pytest process that judges it
(``tests/security/interaction.py`` builds the worker from ``src/``), so code in the file
could, at import time or on a call, reach the test runner itself. Three **reach rules**
therefore apply, read as bytes:

6. no import, in any form, of ``pytest``, ``_pytest``, ``sys``, ``importlib``,
   ``builtins``, ``gc``, ``inspect``, ``ctypes``, ``types``, ``runpy``, ``unittest``
   (``unittest.mock`` included) or ``mock``, or a submodule of one, nor one of them
   reached by name from another module (``from logging import sys``) or as another
   module's attribute. ``unittest.mock.patch`` can rewrite the runner's report objects
   without spelling ``_pytest`` or any dynamic name, so it is a runner module here;
7. none of the names that run text as code, rebind a name at runtime, or reach an
   attribute or a namespace by a string or wholesale: ``exec``, ``eval``, ``compile``,
   ``__import__``, ``globals``, ``locals``, ``vars``, ``dir``, ``getattr``, ``setattr``,
   ``delattr`` and ``__builtins__``, whether called or handed on (``run = exec``), in any
   position; and no ``type(...)`` call with three arguments, which builds a class at
   runtime;
8. no dunder attribute access: ``__dict__``, ``__globals__``, ``__code__``,
   ``__builtins__`` and ``__class__`` are the doors into a module's or a function's
   bindings, and no other ``x.__name__`` has a place in the file; and no **frame access**:
   ``currentframe`` and ``_getframe`` (``logging.currentframe()`` is a permitted module's
   own door to the caller's frame), the frame attributes ``f_builtins``, ``f_globals``,
   ``f_locals``, ``f_back`` and ``f_code``, and ``tb_frame``, ``gi_frame``, ``cr_frame``
   and ``ag_frame``, which reach a frame from a traceback, a generator or a coroutine. A
   frame's builtins table holds ``__import__`` under a string key, so
   ``logging.currentframe().f_builtins["__import__"]("_pytest.reports")`` spells no runner
   module, no dynamic name and no dunder attribute; the frame names are the finding;
9. an **import allowlist**: the worker imports exactly what the shipped starter imports
   plus ``from common.redactor import redact``, each name from its module under its own
   name (``PERMITTED_IMPORTS``, read from the starter when this Task was built and pinned
   here and in the unit tests). Any other module, any other name from a permitted module,
   a relative import, a ``*`` import or an alias of a permitted import is a finding. The
   lesson's change is two calls of one supplied function; no other import has a place in
   the file, and every path to the runner that goes through a module not on the list
   (``from operator import attrgetter``, then ``attrgetter("sys.modules")(logging)``) is
   closed by this rule rather than by a name the reach rules would have to know.

The rules are syntactic: they close the spelled doors, and the trusted observation in
``tests/security/guardrail_observation.py`` checks the worker's behaviour. Together, rules
6, 7 and 9 bound the class the review named: no module beyond the starter's can be
imported, and no dynamic attribute access can be spelled. What stays residual is a worker
that reaches the runner only through the objects the harness hands in, using nothing but
the permitted imports and plain attribute access; the instructor reads the code, and the
graded artifact is the committed tree. A full comparison of the worker against the
trusted starter's syntax tree (permitting only the redactor import and the two redaction
assignments) would close that too and was weighed at review; it is not made here, because
it would also refuse every harmless rewording of the carried comments and local names.
``src/api/routes.py`` is supplied, settled code in this Task and is not student-editable,
so it is no longer read here.

``python -m tests.security.worker_binding`` (``poe worker-binding``) checks the worker (or
the file named on the command line), prints the findings and exits 1 when there is one;
``tests/contract/test_redaction_tests.py`` asserts the same as one assessed row, before it
runs the observation.
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TASK_ROOT = Path(__file__).resolve().parents[2]
WORKER_PATH = Path("src/worker/use_cases.py")
APPLICATION_PATHS: tuple[Path, ...] = (WORKER_PATH,)
APPLICATION_CLASS = "WorkerApplication"
PROCESS_METHOD = "process"
# The provider call inside `process`; a `redact(...)` call's side is its position relative
# to it (tests/security/redaction_mutation.py judges the mutations the same way).
PROVIDER_CALL = "summarize"
# Modules whose import gives application code a path to the test runner, the interpreter's
# module table, or another module's bindings. The top-level name is matched, so every
# submodule (`_pytest.reports`, `importlib.util`, `ctypes.util`, `unittest.mock`) is
# covered. `unittest` is here for `unittest.mock`: `patch("_pytest.reports...")` reaches
# the runner's report objects by a string, with no import of `_pytest` and no dynamic
# name; `mock` is the same library's standalone distribution.
MODULE_TABLE = "modules"
RUNNER_MODULES: frozenset[str] = frozenset(
    {
        "pytest",
        "_pytest",
        "sys",
        "importlib",
        "builtins",
        "gc",
        "inspect",
        "ctypes",
        "types",
        "runpy",
        "unittest",
        "mock",
    }
)
# Names that run text as code, rebind a name at runtime, or reach an attribute or a whole
# namespace by a string (`getattr(logging, "sys")`, `vars(logging)`); none has a place in
# the worker, as a call or handed on under another name.
DYNAMIC_NAMES: frozenset[str] = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
        "__builtins__",
    }
)
# `type(name, bases, namespace)` builds a class at runtime; the one-argument form is an
# ordinary call and stays permitted.
CLASS_BUILDER = "type"
CLASS_BUILDER_ARGUMENTS = 3
# Rule 9: the import allowlist. These are the shipped starter's import statements, read
# from the starter when this Task was built, plus the one import the lesson adds; the unit
# tests pin them again. The worker may import exactly these, each name under its own name;
# `_permitted_imports` reads the tuple into the module and name tables the rule applies.
PERMITTED_IMPORTS: tuple[str, ...] = (
    "import logging",
    "from collections.abc import Callable",
    "from datetime import datetime",
    "from enum import StrEnum",
    "from typing import Protocol",
    "from common.audit import AuditEvent, AuditRecorder, answer_digest",
    "from common.redactor import redact",
    "from domain.contracts import ExceptionJob, ExceptionState, ModelRequest, SensorReading",
    "from domain.errors import TerminalProviderError",
    "from domain.failures import RetrievalUnavailable",
    "from domain.repositories import ExceptionRepository",
    "from ports import ModelProvider",
    "from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, validate_summary",
    "from worker.procedures import ProcedureExcerpt",
)
ALLOWLIST_HINT = (
    "the worker may import exactly what the starter imports plus `from common.redactor "
    "import redact`, each name under its own name; a new module, a new name or an alias "
    "is a finding"
)
# The dunder attributes the reach rule names first; every other dunder attribute is
# refused the same way (`_is_dunder`).
INTERNAL_ATTRIBUTES: frozenset[str] = frozenset(
    {"__dict__", "__globals__", "__code__", "__builtins__", "__class__"}
)
# The names that reach a frame or what a frame holds: the two frame getters a permitted
# module exposes (`logging.currentframe`, `sys._getframe`), the frame's own attributes,
# and the frame attribute of a traceback, a generator and a coroutine. A frame's builtins
# table reaches `__import__` by a string key with no dunder attribute spelled.
FRAME_NAMES: frozenset[str] = frozenset(
    {
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
    }
)
# Which side of the provider call a `redact(...)` call is on (`call_side`).
Side = Literal["note", "answer"]
# Names that rebind a module or a global at runtime beyond the dynamic names (the module
# names are also refused as imports; `modules` is `sys.modules` by attribute).
REBINDING_NAMES: frozenset[str] = frozenset({"importlib", "sys", "builtins", "modules"})
REACH_HINT = (
    "application code must not reach the test runner, the interpreter's module table, or "
    "another module's bindings"
)


@dataclass(frozen=True)
class Binding:
    """One supplied name the worker must import from one module and never rebind."""

    module: str
    name: str
    hint: str

    @property
    def package(self) -> str:
        """Return the module's top-level package (`common`, `worker`)."""
        return self.module.split(".", 1)[0]

    @property
    def leaf(self) -> str:
        """Return the module's last component (`redactor`, `guardrail`)."""
        return self.module.rsplit(".", 1)[-1]


REDACTOR = Binding(
    module="common.redactor",
    name="redact",
    hint=(
        "`from common.redactor import redact` (with any other names from that module) is "
        "the one way the worker may reach the supplied redactor"
    ),
)
GUARDRAIL = Binding(
    module="worker.guardrail",
    name="validate_summary",
    hint=(
        "`from worker.guardrail import validate_summary` (with any other names from that "
        "module) is the one way the worker may reach the supplied guardrail"
    ),
)
BINDINGS: tuple[Binding, ...] = (REDACTOR, GUARDRAIL)
PLACEMENT_HINT = (
    f"call the redactor inside `{APPLICATION_CLASS}.{PROCESS_METHOD}`, where the note is "
    "first read and where the answer comes back"
)
ORDER_HINT = (
    f"redact the provider's raw answer before `{GUARDRAIL.name}` checks it, so the guardrail "
    "sees the text that will be stored; never redact the validated summary"
)
DEFERRED_HINT = (
    f"call `{REDACTOR.name}(...)` directly in `{PROCESS_METHOD}`, where the note is first "
    "read and where the answer comes back; a call inside a lambda or a nested function runs "
    "when that is called, not where it is written, so it has no side and can run after "
    f"`{GUARDRAIL.name}`"
)


class WorkerBindingError(ValueError):
    """Report that the worker file could not be read, as opposed to a finding about it."""


def _line(node: ast.AST) -> str:
    """Return ``line N`` for a node, for a finding."""
    return f"line {getattr(node, 'lineno', '?')}"


def _is_dunder(name: str) -> bool:
    """Return whether ``name`` is a dunder (``__dict__``)."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def _parameters(arguments: ast.arguments) -> list[ast.arg]:
    """Return every parameter of a signature, ``*args`` and ``**kwargs`` included."""
    parameters = [*arguments.posonlyargs, *arguments.args]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    parameters.extend(arguments.kwonlyargs)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return parameters


def _names_module(node: ast.ImportFrom, binding: Binding) -> bool:
    """Return whether a relative import reaches the binding's module or its function."""
    last = (node.module or "").rsplit(".", 1)[-1]
    names = {alias.name for alias in node.names}
    return last == binding.leaf or binding.leaf in names or binding.name in names


def _import_findings(tree: ast.Module, binding: Binding) -> list[str]:
    """Return every import that reaches the binding's module other than the one permitted form."""
    findings: list[str] = []
    imported: list[ast.ImportFrom] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                is_package = alias.name == binding.package
                if is_package or alias.name.startswith(f"{binding.package}."):
                    findings.append(
                        f"{_line(node)}: `import {alias.name}` is not permitted; {binding.hint}"
                    )
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            if node.level:
                if _names_module(node, binding):
                    findings.append(
                        f"{_line(node)}: a relative import of `{binding.module}` is not "
                        f"permitted; {binding.hint}"
                    )
            elif module == binding.package and any(
                alias.name == binding.leaf for alias in node.names
            ):
                findings.append(
                    f"{_line(node)}: `from {binding.package} import {binding.leaf}` is not "
                    f"permitted; {binding.hint}"
                )
            elif module == binding.module:
                imported.append(node)
            else:
                for alias in node.names:
                    if binding.name in (alias.name, alias.asname):
                        findings.append(
                            f"{_line(node)}: `{binding.name}` imported from `{module}` is not "
                            f"the supplied `{binding.module}`; {binding.hint}"
                        )
    top_level = [node for node in tree.body if isinstance(node, ast.ImportFrom)]
    bound = [
        node
        for node in imported
        if any(alias.name == binding.name and alias.asname is None for alias in node.names)
    ]
    if not bound:
        findings.append(
            f"the worker does not import `{binding.name}` from `{binding.module}`; {binding.hint}"
        )
    elif len(bound) > 1:
        findings.append(
            f"`{binding.name}` is imported {len(bound)} times; import it once, at module level"
        )
    for node in imported:
        if node not in top_level:
            findings.append(
                f"{_line(node)}: the `{binding.module}` import must be at module level, not "
                "inside a function or a block"
            )
        for alias in node.names:
            if alias.name == "*":
                findings.append(f"{_line(node)}: `from {binding.module} import *` is not permitted")
            elif alias.asname is not None and binding.name in (alias.name, alias.asname):
                findings.append(
                    f"{_line(node)}: `{alias.name} as {alias.asname}` rebinds `{binding.name}`; "
                    f"import `{binding.name}` under its own name"
                )
    return findings


def _binding_findings(tree: ast.Module, binding: Binding) -> list[str]:
    """Return every binding of the name other than its import, and every non-call use."""
    findings: list[str] = []
    callees: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == binding.name:
                callees.add(id(node.func))

    def rebinds(node: ast.AST, how: str) -> None:
        findings.append(
            f"{_line(node)}: {how} rebinds `{binding.name}`; the name must stay the supplied "
            f"`{binding.module}` import"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == binding.name:
            if isinstance(node.ctx, ast.Store | ast.Del):
                rebinds(node, "an assignment to the name")
            elif id(node) not in callees:
                findings.append(
                    f"{_line(node)}: `{binding.name}` is used other than as the callee of a "
                    f"call; call `{binding.name}(...)` directly"
                )
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name == binding.name
            ):
                rebinds(node, "a function definition")
            for parameter in _parameters(node.args):
                if parameter.arg == binding.name:
                    rebinds(parameter, "a parameter")
        elif isinstance(node, ast.ClassDef) and node.name == binding.name:
            rebinds(node, "a class definition")
        elif isinstance(node, ast.ExceptHandler) and node.name == binding.name:
            rebinds(node, "an exception handler")
        elif isinstance(node, ast.Global | ast.Nonlocal) and binding.name in node.names:
            rebinds(node, "a global or nonlocal statement")
        elif isinstance(node, ast.MatchAs | ast.MatchStar) and node.name == binding.name:
            rebinds(node, "a match capture")
        elif isinstance(node, ast.Attribute):
            if node.attr == binding.name and isinstance(node.ctx, ast.Store | ast.Del):
                rebinds(node, "an attribute assignment")
    return findings


def _rebinding_door_findings(tree: ast.Module) -> list[str]:
    """Return every use of a name that rebinds a module or a global at runtime (rule 4)."""
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and (
            node.attr in REBINDING_NAMES
            or (isinstance(node.value, ast.Name) and node.value.id in REBINDING_NAMES)
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in the worker; it "
                "can rebind a module or a global at runtime"
            )
        if isinstance(node, ast.Name) and node.id in REBINDING_NAMES and node.id != "modules":
            findings.append(
                f"{_line(node)}: `{node.id}` is not permitted in the worker; it can rebind a "
                "module or a global at runtime"
            )
    return findings


def process_method(tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return ``WorkerApplication.process``, or None when the module does not define it."""
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == APPLICATION_CLASS:
            for item in node.body:
                if (
                    isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                    and item.name == PROCESS_METHOD
                ):
                    return item
    return None


def placement_findings(tree: ast.Module) -> list[str]:
    """Return every ``redact(...)`` call outside ``WorkerApplication.process`` (rule 5)."""
    process = process_method(tree)
    inside = (
        {id(node) for node in ast.walk(process) if isinstance(node, ast.Call)}
        if process is not None
        else set()
    )
    findings: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == REDACTOR.name
            and id(node) not in inside
        ):
            findings.append(
                f"{_line(node)}: `{REDACTOR.name}(...)` is called outside "
                f"`{APPLICATION_CLASS}.{PROCESS_METHOD}`; {PLACEMENT_HINT}"
            )
    return findings


def _redact_calls(node: ast.AST) -> list[ast.Call]:
    """Return every call spelled ``redact(...)`` under ``node`` (in ``ast.walk`` order)."""
    return [
        item
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Name)
        and item.func.id == REDACTOR.name
    ]


def _position(node: ast.AST) -> tuple[int, int]:
    """Return a node's start position, for ordering nodes of one source."""
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _end_position(node: ast.AST) -> tuple[int, int]:
    """Return a node's end position, for ordering nodes of one source."""
    return (getattr(node, "end_lineno", 0), getattr(node, "end_col_offset", 0))


def guardrail_call(
    process: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.Call | None:
    """Return the first ``validate_summary(...)`` call in ``process``, or None."""
    calls = [
        node
        for node in ast.walk(process)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == GUARDRAIL.name
    ]
    return min(calls, key=_position) if calls else None


def provider_call(process: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
    """Return the first ``<x>.summarize(...)`` call in ``process``, or None when it has none."""
    calls = [
        node
        for node in ast.walk(process)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == PROVIDER_CALL
    ]
    return min(calls, key=_position) if calls else None


def call_side(call: ast.Call, provider: ast.Call) -> Side:
    """Return which side of the provider call a call in ``process`` is on.

    The one classifier the binding rules, the observation and the two mutations share: a
    call that starts after the provider call ends is on the answer side; any other call
    (before the provider call, inside its argument list, or on its line ahead of it) is on
    the note side. A call on the provider call's own line is therefore read the same way
    everywhere.
    """
    return "answer" if _position(call) >= _end_position(provider) else "note"


def answer_side_calls(tree: ast.Module) -> list[ast.Call]:
    """Return the ``redact(...)`` calls in ``process`` on the answer side of the provider call.

    The answer side is what ``call_side`` names, as the ``answer-redaction-removed``
    mutation sees it. A worker without ``process`` or without a provider call has no
    answer side: the empty list.
    """
    process = process_method(tree)
    if process is None:
        return []
    provider = provider_call(process)
    if provider is None:
        return []
    return [call for call in _redact_calls(process) if call_side(call, provider) == "answer"]


def deferred_findings(tree: ast.Module) -> list[str]:
    """Return every ``redact(...)`` call inside a lambda or a nested function in ``process`` (5c).

    The call is spelled in ``process`` but runs when the lambda or the function is called,
    so its position relative to the provider call and the guardrail call says nothing
    about when it runs. A worker without ``process`` is left to the other rules.
    """
    process = process_method(tree)
    if process is None:
        return []
    findings: list[str] = []
    for node in ast.walk(process):
        if node is process or not isinstance(
            node, ast.Lambda | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            continue
        what = "a lambda" if isinstance(node, ast.Lambda) else f"the nested function `{node.name}`"
        for call in _redact_calls(node):
            findings.append(
                f"{_line(call)}: `{REDACTOR.name}(...)` is called inside {what} in "
                f"`{APPLICATION_CLASS}.{PROCESS_METHOD}`, so the redaction is deferred; "
                f"{DEFERRED_HINT}"
            )
    return findings


def order_findings(tree: ast.Module) -> list[str]:
    """Return every ``redact(...)`` call that comes after the guardrail call (rule 5b).

    A call inside the guardrail call's own argument list (``validate_summary(redact(x))``)
    is before it. A worker without ``process`` or without a ``validate_summary`` call in
    it is left to the other rules and to the observation.
    """
    process = process_method(tree)
    if process is None:
        return []
    guardrail = guardrail_call(process)
    if guardrail is None:
        return []
    inside = {id(node) for node in ast.walk(guardrail)}
    end = _end_position(guardrail)
    findings: list[str] = []
    for call in _redact_calls(process):
        if id(call) in inside or _position(call) < end:
            continue
        findings.append(
            f"{_line(call)}: `{REDACTOR.name}(...)` is called after `{GUARDRAIL.name}`; the "
            f"guardrail then checks a text other than the one stored; {ORDER_HINT}"
        )
    return findings


def _top_module(dotted: str) -> str:
    """Return the first component of a dotted module path."""
    return dotted.split(".", 1)[0]


def _permitted_imports(
    statements: tuple[str, ...] = PERMITTED_IMPORTS,
) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
    """Return the permitted plain-import modules and, per module, the permitted names.

    Each statement is parsed as Python, so the tuple cannot drift from what the rule
    applies; a statement that is not one import, or carries an alias, is a programming
    error here and is refused at import time.
    """
    modules: set[str] = set()
    names: dict[str, set[str]] = {}
    for statement in statements:
        [node] = ast.parse(statement).body
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    raise ValueError(f"PERMITTED_IMPORTS carries an alias: {statement!r}")
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.asname is not None or alias.name == "*":
                    raise ValueError(f"PERMITTED_IMPORTS carries an alias or `*`: {statement!r}")
                names.setdefault(node.module, set()).add(alias.name)
        else:
            raise ValueError(f"PERMITTED_IMPORTS holds a statement that is no import: {statement}")
    return frozenset(modules), {module: frozenset(found) for module, found in names.items()}


PERMITTED_MODULES, PERMITTED_NAMES = _permitted_imports()


def import_allowlist_findings(tree: ast.Module) -> list[str]:
    """Return every import that is not one of the permitted imports under its own name (rule 9).

    A plain import of a module not on the list, a ``from`` import of a module not on the
    list or of a name the list does not give for that module, a relative import, a ``*``
    import and an alias of a permitted import are each a finding. The import's own text is
    quoted; nothing else of the file is.
    """
    findings: list[str] = []

    def outside(node: ast.AST, what: str) -> None:
        findings.append(
            f"{_line(node)}: `{ast.unparse(node)}` {what} the worker's import allowlist; "
            f"{ALLOWLIST_HINT}"
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    outside(node, f"aliases `{alias.name}`, which is not permitted by")
                elif alias.name not in PERMITTED_MODULES:
                    outside(node, "is not in")
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                outside(node, "is a relative import, which is not in")
                continue
            permitted = PERMITTED_NAMES.get(node.module)
            if permitted is None:
                outside(node, "is not in")
                continue
            for alias in node.names:
                if alias.asname is not None:
                    outside(node, f"aliases `{alias.name}`, which is not permitted by")
                elif alias.name == "*":
                    outside(node, "imports every name, which is not permitted by")
                elif alias.name not in permitted:
                    outside(node, f"imports `{alias.name}`, which is not in")
    return findings


def _builds_a_class(node: ast.Call) -> bool:
    """Return whether a call is ``type(...)`` with three arguments (or a starred argument)."""
    if not (isinstance(node.func, ast.Name) and node.func.id == CLASS_BUILDER):
        return False
    starred = any(isinstance(argument, ast.Starred) for argument in node.args)
    return starred or len(node.args) >= CLASS_BUILDER_ARGUMENTS


def reach_findings(tree: ast.Module) -> list[str]:
    """Return every spelled path from the worker to the runner or another module's bindings.

    Rules 6 to 8 of the module docstring: an import of a runner module or a submodule of
    one, a runner module reached by name or attribute through another module, a dynamic
    name in any position, the three-argument ``type(...)`` call, a dunder attribute
    access, and a frame name (``currentframe``, ``f_builtins``, ``tb_frame``, ...) as an
    attribute or a name.
    """
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _builds_a_class(node):
            findings.append(
                f"{_line(node)}: `{CLASS_BUILDER}(...)` with three arguments is not permitted "
                f"in application code; it builds a class at runtime; {REACH_HINT}"
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _top_module(alias.name) in RUNNER_MODULES:
                    findings.append(
                        f"{_line(node)}: `import {alias.name}` is not permitted in application "
                        f"code; the module can reach the test runner or rebind a module or a "
                        f"global at runtime; {REACH_HINT}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and _top_module(node.module or "") in RUNNER_MODULES:
                names = ", ".join(alias.name for alias in node.names)
                findings.append(
                    f"{_line(node)}: `from {node.module} import {names}` is not permitted in "
                    f"application code; the module can reach the test runner or rebind a module "
                    f"or a global at runtime; {REACH_HINT}"
                )
            else:
                for alias in node.names:
                    if alias.name in RUNNER_MODULES or alias.name == MODULE_TABLE:
                        findings.append(
                            f"{_line(node)}: importing `{alias.name}` from `{node.module}` is "
                            f"not permitted in application code; a runner module reached "
                            f"through another module is the same door; {REACH_HINT}"
                        )
        elif isinstance(node, ast.Name) and node.id in DYNAMIC_NAMES:
            findings.append(
                f"{_line(node)}: `{node.id}` is not permitted in application code; it runs text "
                f"as code, rebinds a module or a global at runtime, or reaches an attribute or "
                f"a namespace by a string; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in RUNNER_MODULES or node.attr == MODULE_TABLE
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"runner module or the module table reached as another module's attribute is "
                f"the same door as importing it; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in INTERNAL_ATTRIBUTES or _is_dunder(node.attr)
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"dunder attribute reaches a module's, a class's or a function's bindings; "
                f"{REACH_HINT}"
            )
        elif (isinstance(node, ast.Attribute) and node.attr in FRAME_NAMES) or (
            isinstance(node, ast.Name) and node.id in FRAME_NAMES
        ):
            findings.append(
                f"{_line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"frame, its builtins, globals or locals, or the frame of a traceback, a "
                f"generator or a coroutine reaches the interpreter's bindings; {REACH_HINT}"
            )
    return findings


def findings_for_source(source: str | bytes, path: Path = WORKER_PATH) -> list[str]:
    """Return every reason the worker file fails its rules, deduplicated, in first position."""
    if path.name != WORKER_PATH.name:
        raise WorkerBindingError(
            f"{path.name} is not the worker file of this Task ({WORKER_PATH.as_posix()})"
        )
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"{path.as_posix()} is not valid Python: {exc}"]
    except ValueError as exc:
        return [f"{path.as_posix()} could not be decoded as UTF-8: {exc}"]
    found: list[str] = []
    for binding in BINDINGS:
        found.extend(_import_findings(tree, binding))
        found.extend(_binding_findings(tree, binding))
    found.extend(_rebinding_door_findings(tree))
    found.extend(placement_findings(tree))
    found.extend(order_findings(tree))
    found.extend(deferred_findings(tree))
    found.extend(reach_findings(tree))
    found.extend(import_allowlist_findings(tree))
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in found:
        if finding not in seen:
            seen.add(finding)
            ordered.append(finding)
    return ordered


def findings(path: Path) -> list[str]:
    """Return the findings for the worker file at ``path``, read as bytes."""
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise WorkerBindingError(f"{path.as_posix()} could not be read: {exc}") from exc
    return findings_for_source(source, path)


def application_findings(root: Path = TASK_ROOT) -> list[str]:
    """Return the worker's findings under ``root``, each prefixed by the file's path."""
    found: list[str] = []
    for relative in APPLICATION_PATHS:
        found.extend(f"{relative.as_posix()}: {item}" for item in findings(root / relative))
    return found


def main(argv: list[str] | None = None) -> int:
    """Check the worker file (or the file named) and print the findings."""
    parser = argparse.ArgumentParser(
        description=(
            "Check that the worker binds the supplied redactor and guardrail by their imported "
            "names and reaches nothing beyond application code."
        )
    )
    parser.add_argument(
        "paths", nargs="*", type=Path, default=[TASK_ROOT / path for path in APPLICATION_PATHS]
    )
    arguments = parser.parse_args(argv)
    exit_code = 0
    for path in arguments.paths:
        try:
            found = findings(path)
        except WorkerBindingError as exc:
            print(f"worker-binding: {exc}", file=sys.stderr)
            return 2
        label = WORKER_PATH.as_posix()
        if found:
            exit_code = 1
            print(
                f"worker-binding: {label} does not bind the supplied redactor and guardrail by "
                "their imported names, or reaches beyond application code:",
                file=sys.stderr,
            )
            for finding in found:
                print(f"- {finding}", file=sys.stderr)
            continue
        print(
            f"worker-binding: {label} imports `{REDACTOR.name}` from `{REDACTOR.module}` and "
            f"`{GUARDRAIL.name}` from `{GUARDRAIL.module}`, rebinds nothing, calls the redactor "
            f"directly inside `{APPLICATION_CLASS}.{PROCESS_METHOD}` only and never after "
            f"`{GUARDRAIL.name}`, imports nothing outside the starter's imports and the "
            "redactor's, and reaches nothing beyond application code."
        )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
