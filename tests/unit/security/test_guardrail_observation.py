"""Coldline.

===================

File:              tests/unit/security/test_guardrail_observation.py
Component:         Unit tests — Trusted guardrail observation
Purpose:           Prove the observation names a worker that parses the provider's answer on
                    its own behind a dummy guardrail call, one that hands the answer over and
                    then ignores the verdict, and one that redacts on the answer side yet hands
                    the raw answer over; and accepts a hand-over of the redacted answer.
Interacts With:    tests/security/guardrail_observation.py, tests/security/interaction.py,
                    tests/security/worker_binding.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Behavioural evidence beside static evidence, spies at a verified binding,
                    inverted verdicts, counterexamples that static rules accept
Tools:             Python 3.12, pytest, asyncio

The workers here are probes: source text in this file, executed into a module of its own,
the way an import would bind it. None is the Task's worker, and the shipped
``src/worker/use_cases.py`` is never read or run here (the assessed row runs it). Each
spells the permitted imports and uses ``validate_summary`` only as a callee, so only what
happens at run time tells them from a worker that routes every answer through the supplied
guardrail and stores what it answered (the fourth probe, which redacts the validated
summary, is also named by the static order rule). No correct worker is built here: every
probe stores the text and ignores the verdict, which is what the inverted runs name.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import ModuleType

import pytest

from adapters.model.deterministic import RESPONSES
from common.redactor import redact
from domain.contracts import ExceptionState
from tests.security import guardrail_observation as observation
from tests.security import worker_binding as binding
from tests.security.interaction import TASK_ROOT

# What the probes share: the harness's constructor signature, one provider call built as
# the worker builds it, and the permitted imports. Each probe adds its own ending.
_WORKER_BODY = '''
from common.redactor import redact
from domain.contracts import ExceptionState, ModelRequest
from worker.guardrail import validate_summary


class WorkerApplication:
    """The smallest worker the harness can run; it implements no output policy."""

    def __init__(self, repository, provider, procedures, *, audit, clock, maximum_attempts=3):
        """Keep the collaborators the harness hands over."""
        self._repository = repository
        self._provider = provider
        self._procedures = procedures

    async def process(self, job, *, delivery_count):
        """Call the provider once, then do what this probe does with its answer."""
        await self._repository.transition(
            job.exception_id, {ExceptionState.QUEUED}, ExceptionState.PROCESSING
        )
        procedure = await self._procedures.find(job.reading)
        answer = await self._provider.summarize(
            ModelRequest(
                exception_id=job.exception_id,
                shipment_id=job.reading.shipment_id,
                temperature_c=job.reading.temperature_c,
                allowed_min_c=job.reading.allowed_min_c,
                allowed_max_c=job.reading.allowed_max_c,
                handling_note=job.reading.handling_note,
                procedure_id=procedure.document_id,
                procedure_excerpt=procedure.text,
                emulator_response=job.reading.emulator_response,
            )
        )
'''

# Counterexample 1: one guardrail call as a switch, handed a constant, and the provider's
# real answer parsed by the worker itself (by string cuts: the import allowlist leaves the
# worker no `json`, which is the point of the allowlist and not of this probe).
OWN_PARSING_WORKER = (
    '"""Probe worker: a dummy guardrail call, the real answer parsed on its own."""\n'
    + _WORKER_BODY
    + """        validate_summary("{}")
        marker = '"summary": "'
        summary = answer.text
        if marker in summary:
            summary = summary.split(marker, 1)[1].split('"', 1)[0]
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=summary,
        )
        return "ACK"
"""
)

# Counterexample 2: the answer is handed over exactly as returned, and the verdict is
# dropped on the floor; the raw text is stored as the summary whatever the guardrail said.
VERDICT_IGNORING_WORKER = (
    '"""Probe worker: the answer handed over once, the verdict ignored, the text stored."""\n'
    + _WORKER_BODY
    + """        validate_summary(answer.text)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=answer.text,
        )
        return "ACK"
"""
)

# Counterexample 3: the answer redacted as supplied is handed over (the Task 4.4 shape of
# the hand-over, which the observation accepts), and the verdict is ignored all the same.
REDACTED_HAND_OVER_WORKER = (
    '"""Probe worker: the redacted answer handed over, the verdict ignored, the text stored."""\n'
    + _WORKER_BODY
    + """        validate_summary(redact(answer.text))
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=answer.text,
        )
        return "ACK"
"""
)

# Counterexample 4 (the review's shape): the raw answer is validated, then the validated
# summary is redacted and stored, so the guardrail checked one string and the record
# holds another. The static order rule names it by its source; at run time it is a raw
# hand-over from a worker whose source redacts on the answer side.
VERDICT_REDACTING_WORKER = (
    '"""Probe worker: the raw answer validated, the validated summary redacted and stored."""\n'
    + _WORKER_BODY.replace(
        "from worker.guardrail import validate_summary\n",
        "from worker.guardrail import RejectedSummary, validate_summary\n",
    )
    + """        verdict = validate_summary(answer.text)
        clean = redact(answer.text if isinstance(verdict, RejectedSummary) else verdict.summary)
        await self._repository.transition(
            job.exception_id, {ExceptionState.PROCESSING}, ExceptionState.COMPLETED,
            summary=clean,
        )
        return "ACK"
"""
)

FOLLOW_HINT = "the stored outcome must follow the guardrail's verdict"
HAND_OVER_HINT = "the raw answer text, redacted as supplied, must reach the guardrail"
RAW_DESPITE_REDACTION = (
    "was handed the provider's answer as returned, although the worker redacts on the answer side"
)


def _probe_module(source: str, name: str) -> ModuleType:
    """Execute one probe's source into a module of its own, as an import would bind it."""
    module = ModuleType(name)
    exec(compile(source, f"<{name}>", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize(
    "source",
    [OWN_PARSING_WORKER, VERDICT_IGNORING_WORKER, REDACTED_HAND_OVER_WORKER],
    ids=["own-parsing", "verdict-ignored", "redacted-hand-over"],
)
def test_every_counterexample_passes_the_static_binding_check(source: str) -> None:
    """Each probe spells the permitted imports and calls the names: the static rules see nothing.

    The probes call `redact` nowhere or inside `process` only, so the placement rule is
    silent too; this is why the observation exists.
    """
    assert binding.findings_for_source(source) == []


async def test_a_dummy_guardrail_call_beside_own_parsing_is_named_for_every_response() -> None:
    """A worker that hands the guardrail a constant and parses the answer itself fails hand-over.

    Each response gives one finding naming what the guardrail was handed (two characters)
    against what the provider answered; the inverted runs are not made. The stored record
    alone would not have told: the probe ends ``COMPLETED`` with a summary.
    """
    module = _probe_module(OWN_PARSING_WORKER, "probe_own_parsing")

    observed = await observation.observe(module, "valid", root=TASK_ROOT)
    assert observed.record.state is ExceptionState.COMPLETED
    assert observed.record.summary
    assert observed.calls == ((("{}",), {}),)
    assert len(observed.answers) == 1 and observed.answers[0] != "{}"

    findings = await observation.observe_module(module, root=TASK_ROOT)

    assert len(findings) == len(RESPONSES)
    for response, finding in zip(RESPONSES, findings, strict=True):
        assert finding.startswith(
            f"{response}: `validate_summary` was handed a string of 2 characters"
        ), finding
        assert "not the provider's answer (a string of " in finding
        assert "or that answer redacted as supplied" in finding
        assert HAND_OVER_HINT in finding
        assert FOLLOW_HINT not in finding


@pytest.mark.parametrize(
    "source",
    [VERDICT_IGNORING_WORKER, REDACTED_HAND_OVER_WORKER],
    ids=["as-returned", "redacted"],
)
async def test_a_worker_that_ignores_the_verdict_fails_only_the_inverted_runs(source: str) -> None:
    """A worker that hands the answer over (as returned or redacted) and ignores the verdict.

    Hand-over is clean for every response: one provider call, one guardrail call, with the
    captured answer text or its supplied redaction as the one argument. Under the inverted
    verdicts the record does not follow: a validated answer, answered with a rejection, is
    still ``COMPLETED``, and each refused answer, answered with the valid answer's validated
    summary, keeps the raw text instead of the validated fields.
    """
    module = _probe_module(source, "probe_verdict_ignored")
    original = module.validate_summary

    for response in RESPONSES:
        observed = await observation.observe(module, response, root=TASK_ROOT)
        assert observation.hand_over_findings(observed) == []
        assert len(observed.calls) == 1
        assert module.validate_summary is original
        with pytest.raises(observation.ObservationError, match="inverted run"):
            observation.followed_findings(observed)

    findings = await observation.observe_module(module, root=TASK_ROOT)

    assert findings
    assert all(FOLLOW_HINT in finding for finding in findings)
    assert not any(HAND_OVER_HINT in finding for finding in findings)
    code = observation.INVERTED_REJECTION.code
    for validated in ("valid", "pii-echo"):
        assert (
            f"{validated}: with `validate_summary` answering a rejection ({code}), the stored "
            f"record's state is 'COMPLETED', expected 'NEEDS_REVIEW'; {FOLLOW_HINT}"
        ) in findings
    for response in ("malformed", "manipulated"):
        about = [finding for finding in findings if finding.startswith(f"{response}: ")]
        assert about, response
        assert all("answering a validated summary" in finding for finding in about)
        assert not any("record's state is" in finding for finding in about)
        assert any("record's summary is" in finding for finding in about)
        assert any("record's handling_class is None" in finding for finding in about)
        assert any("record's next_step is None" in finding for finding in about)
    assert module.validate_summary is original


# --- The answer-side rule: a worker that redacts on the answer side hands the redacted answer


async def _responses_the_redactor_changes(module: ModuleType) -> set[str]:
    """Return the responses whose captured answer the supplied redactor changes.

    A raw hand-over of an answer the redactor leaves as it is cannot be told from the
    redacted hand-over (the two texts are equal), so only these responses can name it.
    The scenario's own note names a contact, so the `valid` answer is among them, as is
    `pii-echo`.
    """
    changed: set[str] = set()
    for response in RESPONSES:
        observed = await observation.observe(module, response, root=TASK_ROOT)
        [answer] = observed.answers
        if redact(answer) != answer:
            changed.add(response)
    assert {"valid", "pii-echo"} <= changed, changed
    return changed


async def test_a_raw_hand_over_is_named_when_the_worker_redacts_on_the_answer_side() -> None:
    """With `answer_redacted` the answer as returned is no longer an accepted hand-over.

    The same observed runs are judged both ways: accepted for a worker whose source has
    no answer-side `redact` call (the variant's shape), one finding per response whose
    answer the redactor changes for one that has (the review's shape, which redacts
    `verdict.summary` after the fact). The inverted runs are not made when the hand-over
    failed.
    """
    module = _probe_module(VERDICT_IGNORING_WORKER, "probe_raw_hand_over")
    changed = await _responses_the_redactor_changes(module)

    for response in RESPONSES:
        observed = await observation.observe(module, response, root=TASK_ROOT)
        assert observation.hand_over_findings(observed) == []
        strict = observation.hand_over_findings(observed, answer_redacted=True)
        if response not in changed:
            assert strict == [], response
            continue
        [finding] = strict
        assert finding.startswith(f"{response}: `validate_summary` {RAW_DESPITE_REDACTION}")
        assert HAND_OVER_HINT in finding

    findings = await observation.observe_module(module, root=TASK_ROOT, answer_redacted=True)

    assert len(findings) == len(changed)
    assert all(RAW_DESPITE_REDACTION in finding for finding in findings)
    assert not any(FOLLOW_HINT in finding for finding in findings)


async def test_the_redacted_hand_over_satisfies_the_answer_side_rule() -> None:
    """A worker that hands `redact(answer.text)` over passes the hand-over under either rule."""
    module = _probe_module(REDACTED_HAND_OVER_WORKER, "probe_redacted_hand_over_strict")

    for response in RESPONSES:
        observed = await observation.observe(module, response, root=TASK_ROOT)
        assert observation.hand_over_findings(observed, answer_redacted=True) == []
        assert observation.hand_over_findings(observed, answer_redacted=False) == []

    # A text of the worker's own making is named under the stricter rule too, by its shape.
    own = _probe_module(OWN_PARSING_WORKER, "probe_own_parsing_strict")
    observed = await observation.observe(own, "valid", root=TASK_ROOT)
    [finding] = observation.hand_over_findings(observed, answer_redacted=True)
    assert "was handed a string of 2 characters (digest " in finding
    assert "not the provider's answer redacted as supplied" in finding
    assert RAW_DESPITE_REDACTION not in finding


async def test_redacting_the_validated_summary_is_named_statically_and_at_run_time() -> None:
    """The review's worker: `validate_summary(answer.text)`, then `redact(verdict.summary)`.

    The static order rule names the call after the guardrail call; its source has a
    `redact` call on the answer side, so the observation requires the redacted answer and
    names the raw hand-over for every response.
    """
    found = binding.findings_for_source(VERDICT_REDACTING_WORKER)
    assert len(found) == 1 and "`redact(...)` is called after `validate_summary`" in found[0]
    assert binding.answer_side_calls(ast.parse(VERDICT_REDACTING_WORKER))

    module = _probe_module(VERDICT_REDACTING_WORKER, "probe_verdict_redacting")
    changed = await _responses_the_redactor_changes(module)
    findings = await observation.observe_module(module, root=TASK_ROOT, answer_redacted=True)
    assert len(findings) == len(changed)
    assert all(RAW_DESPITE_REDACTION in finding for finding in findings)
    assert {finding.split(":", 1)[0] for finding in findings} == changed


def test_redacts_the_answer_reads_the_imported_modules_file(tmp_path: Path) -> None:
    """The flag comes from the module's own file: a `redact` call after the provider call."""
    for source, expected in (
        (REDACTED_HAND_OVER_WORKER, True),
        (VERDICT_REDACTING_WORKER, True),
        (VERDICT_IGNORING_WORKER, False),
        (OWN_PARSING_WORKER, False),
    ):
        path = tmp_path / "use_cases.py"
        path.write_text(source, encoding="utf-8")
        module = ModuleType("probe_from_file")
        module.__file__ = str(path)
        assert observation.redacts_the_answer(module) is expected, source.splitlines()[0]

    nowhere = ModuleType("probe_without_file")
    with pytest.raises(observation.ObservationError, match="not imported from a file"):
        observation.redacts_the_answer(nowhere)

    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    module = ModuleType("probe_broken")
    module.__file__ = str(broken)
    with pytest.raises(observation.ObservationError, match="could not be parsed"):
        observation.redacts_the_answer(module)
