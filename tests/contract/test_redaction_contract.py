"""Coldline.

===================

File:              tests/contract/test_redaction_contract.py
Component:         Contract tests — PII redaction
Purpose:           One assessed check per public Check-list row that reads the running stack:
                    the N-01 and pii-echo runs end COMPLETED with the expected redacted summary
                    and leave no marked value in any of the four locations, and the inherited
                    Task 3 and Task 2 controls still hold.
Interacts With:    The running API, worker and PostgreSQL, tests/security/live_record.py,
                    tests/security/pii.py, tests/security/pii_scan.py, tests/security/trail.py,
                    tests/security/interaction.py, src/worker/use_cases.py (through the stack)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.4
Concepts:          Redaction before the first copy, marked values as evidence, inherited
                    controls that must not regress
Tools:             Python 3.12, pytest, httpx

Assessed: a fresh starter logs and sends the handling note as written and hands the raw
answer to the guardrail, so the redaction rows fail until ``src/worker/use_cases.py`` holds
the two redaction calls. ``poe contract`` deselects them; ``poe redaction-contract`` and
``poe verify`` run them, right after the smoke checks and before the inherited end-to-end
checks and the student tests, so a wrong outcome is reported by the row that names it.

One module-scoped fixture, ``interactions``, is the trusted harness of the live rows: it
submits four readings through the open intake, each in a trace id of its own choosing
(the supplied note ``N-01`` with the ``valid`` answer, the shipped scenario note with the
``pii-echo`` answer, and ``N-01`` with each refused answer), waits through the database for
a finished state, and makes exactly one authenticated read of each record through the
API, as the dispatcher, again in a trace id of its own. Every live row then judges one of
those interactions on its own. The rows never read a record's state through the route,
they read the trail back through the API container as ``poe audit-trail`` does, and they
read the four locations exactly as ``poe pii-scan`` does. The two scan rows also run the
worker once more in this process (``captured_log_findings``), with ``sys.stdout`` and
``sys.stderr`` redirected for the run, and search every log message of that run and
everything it wrote to either stream, because the live scan can only read the lines that
name the exception and no log check sees a ``print``. A failing row names what reached
where by the marked value's label, never by the value, and a row that compares a stored
summary with the expected one reports the interaction and the guidance, never either
text.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from adapters.model.deterministic import (
    PLANTED_FIELD,
    PLANTED_NEXT_STEP,
    PLANTED_VALUE,
    REJECTED_RESPONSES,
)
from common.audit import AuditEvent
from domain.contracts import SensorReading
from tests.contract.submission_validation import SubmissionError, validate_submission
from tests.runtime_config import host_port
from tests.security import live_record, pii, pii_scan, trail
from tests.security.assessed_run import INTERACTION_IDS
from tests.security.fixtures import EXPECTED_STATUS, FIXTURE_NAMES, bearer_headers
from tests.security.harness import TASK_ROOT
from tests.security.interaction import captured_log_findings, expected_summary, replayed_answer
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE

pytestmark = pytest.mark.assessed
ROUTE = "/api/v1/exceptions/{exception_id}"
DISPATCHER = "dispatcher-valid"
DISPATCHER_SUBJECT = "user:dispatcher-01"
DISPATCHER_ROLE = "dispatcher"
FIRST_NOTE = pii.FIRST_NOTE
ECHO = "pii-echo"
# The four live interactions, by the id the parametrized rows carry: the supplied note (or
# None for the shipped scenario note) and the emulator response.
INTERACTIONS: dict[str, tuple[str | None, str]] = {
    "n01-valid": (FIRST_NOTE, "valid"),
    ECHO: (None, ECHO),
    **{response: (FIRST_NOTE, response) for response in REJECTED_RESPONSES},
}
# The code the supplied guardrail reports for each supplied refused response.
EXPECTED_CODE = {"malformed": "not_json", "manipulated": "unknown_property"}
# The validation event each interaction must produce.
EXPECTED_DECISION = {
    "n01-valid": AuditEvent.OUTPUT_VALIDATED.value,
    ECHO: AuditEvent.OUTPUT_VALIDATED.value,
    "malformed": AuditEvent.OUTPUT_REJECTED.value,
    "manipulated": AuditEvent.OUTPUT_REJECTED.value,
}
# Text the emulator's answers carry and a stored record of a rejected answer must not.
MODEL_TEXT = (
    "Synthetic shipment",
    "thermal_excursion",
    "operational_review",
    PLANTED_FIELD,
    PLANTED_VALUE,
    PLANTED_NEXT_STEP,
    '"summary"',
)
REDACTION_HINT = (
    "redact the handling note where `process` first reads it, before the log line and the "
    "model request, and redact the provider's raw answer before `validate_summary`"
)


@dataclass(frozen=True)
class Interaction:
    """One supplied note and response through the running stack, as the trusted harness made it.

    ``submission`` holds the reading, its ids, and the trace id the intake request was
    sent in; ``state`` is the finished state the database reported; ``read_trace_id`` is
    the trace id the one authenticated read was sent in, and ``body`` what it returned.
    """

    key: str
    note: str | None
    response: str
    submission: live_record.Submission
    state: str
    read_trace_id: str
    body: dict[str, Any]

    @property
    def exception_id(self) -> str:
        """Return the exception the interaction created."""
        return self.submission.exception_id

    @property
    def reading(self) -> SensorReading:
        """Return the reading as it was submitted."""
        return SensorReading.model_validate(self.submission.reading)

    def expected_summary(self) -> str | None:
        """Return the summary a worker that redacts as supplied stores for this reading."""
        return expected_summary(exception_id=self.exception_id, reading=self.reading)

    def expected(self, record: dict[str, Any]) -> trail.ExpectedInteraction:
        """Return what the trail must agree with, from the harness's own knowledge only.

        The raw answer is replayed through the real emulator for the request a correct
        worker sends (the note redacted); the state and summary are the database's; the
        subject and role are the dispatcher fixture's.
        """
        answer = replayed_answer(exception_id=self.exception_id, reading=self.reading)
        summary = record.get("summary")
        return trail.ExpectedInteraction(
            exception_id=self.exception_id,
            reading_id=self.submission.reading_id,
            provider=answer.provider,
            answer_text=answer.text,
            state=str(record.get("state")),
            summary=summary if isinstance(summary, str) else None,
            subject=DISPATCHER_SUBJECT,
            role=DISPATCHER_ROLE,
        )


@pytest.fixture(scope="module")
def api() -> Iterator[httpx.Client]:
    """Return a client for the running API on the host."""
    port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0) as client:
        yield client


def _read_once(api: httpx.Client, exception_id: str, trace_id: str) -> dict[str, Any]:
    """Read one record through the API as the dispatcher, once, in the given trace."""
    response = api.get(
        ROUTE.format(exception_id=exception_id),
        headers={**bearer_headers(DISPATCHER), **live_record.traceparent(trace_id)},
    )
    assert response.status_code == 200, _detail(response)
    body = response.json()
    assert isinstance(body, dict)
    return body


@pytest.fixture(scope="module")
def interactions(api: httpx.Client) -> dict[str, Interaction]:
    """Run the four interactions: submit, wait, and read each once as the dispatcher.

    The wait ends on any finished state; which one each record reached is what the rows
    assert. A record that never finishes is an error on every row, not a row's failure.
    """
    notes = pii.load_notes(TASK_ROOT)
    made: dict[str, Interaction] = {}
    for key, (note, response) in INTERACTIONS.items():
        text = notes[note].text if note is not None else None
        try:
            submission, state = live_record.create_finished_submission(
                api, response=response, note=text
            )
        except live_record.StoredRecordError as exc:
            raise RuntimeError(f"the live rows' precondition was not met: {exc}") from exc
        read_trace_id = live_record.new_trace_id()
        body = _read_once(api, submission.exception_id, read_trace_id)
        made[key] = Interaction(key, note, response, submission, state, read_trace_id, body)
    return made


def _record(exception_id: str) -> dict[str, Any]:
    """Return one record's output fields from the database, or fail the row."""
    try:
        record = live_record.stored_record(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    if record is None:
        pytest.fail(f"exception {exception_id} is not in the database")
    return record


def _detail(response: httpx.Response) -> str:
    """Return the refusal's reason, or the status line, for an assertion message."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:200]


def _trail(exception_id: str) -> list[dict[str, Any]]:
    """Return one exception's audit trail from the running stack, or fail the row."""
    try:
        return trail.fetch_trail(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))


def _locations(exception_id: str) -> dict[str, str]:
    """Return the four locations as `poe pii-scan` reads them, or fail the row.

    A location the scan reports unavailable (no worker log line names the exception, or
    no request record) fails the row here: the scan cannot show absence from evidence
    that is not there, and neither can the row.
    """
    try:
        locations = pii_scan.live_locations(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    assert locations["worker logs"] is not None, (
        f"the worker logs hold no line naming {exception_id}; the worker's job line is "
        "expected whatever the file holds, so the logs could not be read"
    )
    assert locations["model request"] is not None, (
        f"no model request was recorded for {exception_id}: the worker's request log is not "
        "composed (COLDLINE_MODEL_REQUEST_DIR in compose.yaml) or the record could not be read"
    )
    return {name: text for name, text in locations.items() if text is not None}


def _completed_redacted(interaction: Interaction) -> dict[str, Any]:
    """Assert one interaction ended COMPLETED with the expected redacted summary; return it."""
    assert interaction.state == "COMPLETED", (
        f"the {interaction.key} run ended in {interaction.state}; a redacted answer still "
        "passes the schema, so the run must complete"
    )
    record = _record(interaction.exception_id)
    summary = record.get("summary")
    assert isinstance(summary, str) and summary, "no summary was stored"
    # Compared as a boolean, so neither the stored nor the expected text is written into
    # the failure message or pytest's comparison output: on a starter the stored summary
    # carries the marked values, and a failing row's output must not be one more place
    # they reach.
    matches = summary == interaction.expected_summary()
    assert matches, (
        f"the stored summary of the {interaction.key} run is not the one a worker that "
        f"redacts as supplied stores ({REDACTION_HINT})"
    )
    assert record.get("handling_class") == "thermal_excursion"
    assert record.get("next_step") == "operational_review"
    assert record.get("rejection_reason") is None
    assert record.get("failure_reason") is None
    return record


# --- Step 1: the two redaction calls ------------------------------------------------------


@pytest.mark.runtime
def test_note_n01_run_completes_with_the_expected_redacted_summary(
    interactions: dict[str, Interaction],
) -> None:
    """The N-01 run ends `COMPLETED`, and its stored summary is the expected redacted one.

    The expected summary is computed from the reading alone: the emulator replayed over
    the request a correct worker sends (the note redacted), the answer redacted, the
    supplied guardrail's validated `summary`. A worker that sends the note raw stores a
    summary that repeats the note's phone number and email address instead.
    """
    _completed_redacted(interactions["n01-valid"])


@pytest.mark.runtime
def test_note_n01_values_are_absent_from_every_location(
    interactions: dict[str, Interaction],
) -> None:
    """None of N-01's marked values is in the logs, the model request, the trail, or the summary.

    Read exactly as `poe pii-scan` reads them: the worker container's log lines naming the
    exception, the request text the emulator recorded, every audit record's details, and
    the stored summary. The worker logs and the model request are the two places only the
    note-side redaction keeps clean. Then, because the live scan reads only the log lines
    that name the exception and no log check sees a `print`, the worker is run once more
    in this process with N-01, with its standard output and error redirected, and every
    log message any logger emitted during that run and everything the run wrote to either
    stream is searched, whatever it names: a copy of the raw note logged or printed
    without the exception id is a leak the live scan cannot correlate, and this half of
    the row sees it.
    """
    interaction = interactions["n01-valid"]
    locations = _locations(interaction.exception_id)
    values = pii.marked_values(pii.load_notes(TASK_ROOT), note=FIRST_NOTE)
    found = pii.render(pii.findings(locations, values))
    assert found == [], (
        f"marked values of {FIRST_NOTE} reached: " + "; ".join(found) + f" ({REDACTION_HINT})"
    )

    logged = asyncio.run(captured_log_findings(note=FIRST_NOTE, root=TASK_ROOT))
    assert logged == [], (
        f"marked values of {FIRST_NOTE} were logged or printed by the worker where `poe "
        "pii-scan` cannot correlate them with the exception: "
        + "; ".join(logged)
        + f" ({REDACTION_HINT}; log and print nothing from the note before the redaction)"
    )


@pytest.mark.runtime
def test_pii_echo_run_completes_redacted_with_its_contact_in_no_location(
    interactions: dict[str, Interaction],
) -> None:
    """The pii-echo run completes with the redacted summary, and its contact reaches nowhere.

    The response adds a contact number that is in no request, so the worker logs and the
    model request are clean whatever the worker does; only the answer-side redaction
    keeps it out of the stored summary and the `outcome_stored` audit record. The stored
    summary must equal the expected redacted summary, and the scan must find the contact
    in none of the four locations. Then, as in the N-01 row, the worker is run once more
    in this process, with N-01 and the `pii-echo` response together and its standard
    output and error redirected, and every log message any logger emitted during that run
    and everything it wrote to either stream is searched for the contact and for N-01's
    values: the answer carries no exception id, so a copy of the raw answer logged or
    printed before the redaction is a leak the live scan cannot correlate, and this half
    of the row sees it.
    """
    interaction = interactions[ECHO]
    _completed_redacted(interaction)
    locations = _locations(interaction.exception_id)
    values = pii.response_values(ECHO)
    found = pii.render(pii.findings(locations, values))
    assert found == [], f"the {ECHO} contact reached: " + "; ".join(found) + f" ({REDACTION_HINT})"

    logged = asyncio.run(captured_log_findings(note=FIRST_NOTE, response=ECHO, root=TASK_ROOT))
    assert logged == [], (
        f"marked values of {FIRST_NOTE} or the {ECHO} contact were logged or printed by the "
        "worker where `poe pii-scan` cannot correlate them with the exception: "
        + "; ".join(logged)
        + f" ({REDACTION_HINT}; log and print nothing from the note or the answer before the "
        "redaction)"
    )


# --- The inherited Task 3 controls -------------------------------------------------------


@pytest.mark.runtime
@pytest.mark.parametrize("response", REJECTED_RESPONSES)
def test_bad_responses_still_end_needs_review(
    interactions: dict[str, Interaction], response: str
) -> None:
    """The malformed and manipulated answers still end `NEEDS_REVIEW` with the policy's outcome.

    The redaction call sits before the guardrail, so a refused answer is refused as
    before: the fixed message, the guardrail's code, no validated fields, and none of the
    model's text in any stored field.
    """
    interaction = interactions[response]
    assert interaction.state == "NEEDS_REVIEW", (
        f"the {response} response ended in {interaction.state}"
    )
    record = _record(interaction.exception_id)
    # A boolean, so a stored text other than the fixed message is never written into
    # the failure output.
    fixed = record.get("summary") == REVIEW_MESSAGE
    assert fixed, f"the {response} run's stored summary is not the output policy's fixed message"
    reason = record.get("rejection_reason")
    assert isinstance(reason, str) and reason.split(":")[0] in REASON_CODES, reason
    assert reason.split(":")[0] == EXPECTED_CODE[response], reason
    assert record.get("handling_class") is None and record.get("next_step") is None
    assert record.get("failure_reason") is None
    for field, value in record.items():
        if isinstance(value, str) and field != "summary":
            for text in MODEL_TEXT:
                assert text not in value, f"{field} carries the model's text ({text!r})"


@pytest.mark.runtime
@pytest.mark.parametrize("key", INTERACTION_IDS)
def test_the_audit_trail_still_reconstructs_one_interaction(
    interactions: dict[str, Interaction], key: str
) -> None:
    """Each interaction's trail is the four worker events, in order, then the one read.

    Judged against what the harness knows without the trail: every record names the
    exception; the worker's events carry the trace id the reading was submitted in and
    the read the trace id it was requested in; each worker event carries exactly the
    fields the event list permits, as scalars, with the values the harness captured
    independently. The model-response digest is of the answer the emulator gives the
    request a correct worker sends (the note redacted), as `docs/security/audit-events.md`
    states; the stored outcome is the database's.
    """
    interaction = interactions[key]
    assert interaction.body.get("state") == interaction.state
    record = _record(interaction.exception_id)
    records = _trail(interaction.exception_id)
    assert records, (
        f"no audit records for {interaction.exception_id}: the worker recorded no event and "
        "the route recorded no summary read"
    )

    findings = trail.sequence_findings(records, reads=1)
    assert findings == [], "; ".join(findings) + f"\n{trail.events_of(records)}"
    findings = trail.field_findings(records)
    assert findings == [], "; ".join(findings)
    expected = interaction.expected(record)
    findings = trail.value_findings(records, expected)
    assert findings == [], (
        "; ".join(findings)
        + " (the model-response digest is of the answer to the request a worker that "
        "redacts the note as supplied sends)"
    )
    findings = trail.trace_findings(
        records, submission=interaction.submission.trace_id, reads=(interaction.read_trace_id,)
    )
    assert findings == [], "; ".join(findings)

    events = trail.events_of(records)
    assert events[2] == EXPECTED_DECISION[key], events
    # The outcome record carries the stored summary; compared as a boolean so neither
    # copy of the text is written into the failure output.
    outcome_stored = trail.details_of(records[3]) == {
        "state": interaction.state,
        "summary": record.get("summary"),
    }
    assert outcome_stored, (
        f"the {key} run's `outcome_stored` details are not its stored state and summary"
    )
    read = trail.details_of(records[4])
    assert read.get("subject") == DISPATCHER_SUBJECT and read.get("role") == DISPATCHER_ROLE, read


# --- The inherited Task 2 control ---------------------------------------------------------


@pytest.mark.runtime
def test_the_task_2_access_rule_still_protects_the_summary_route(api: httpx.Client) -> None:
    """`dispatcher-valid` reads `200`; the seven other fixtures and a bare request are refused.

    The settled rule from Task 4.2 and the summary-read event from Task 4.3 are supplied
    code in this Task. The exception is created through the open intake and confirmed
    through the database to hold a stored summary before the first request.
    """
    try:
        exception_id = live_record.create_stored_exception(api)
    except live_record.StoredRecordError as exc:
        pytest.fail(f"the access row's precondition was not met: {exc}")
    for fixture in FIXTURE_NAMES:
        response = api.get(ROUTE.format(exception_id=exception_id), headers=bearer_headers(fixture))
        assert response.status_code == EXPECTED_STATUS[fixture], (
            f"{fixture}: {response.status_code} {_detail(response)}"
        )
        if EXPECTED_STATUS[fixture] != 200:
            assert "exception_id" not in response.text, f"{fixture}: the record was returned"
    bare = api.get(ROUTE.format(exception_id=exception_id))
    assert bare.status_code == 401, f"no token: {bare.status_code} {_detail(bare)}"
    assert "exception_id" not in bare.text


# --- The answer sheet ----------------------------------------------------------------------


def test_submission_answers_use_the_allowed_values() -> None:
    """`submission.yaml` names a supplied note, a limitation type and a documented limitation.

    The public format check: the three answers are present, each one of its allowed
    values, and the sheet is not a copy of the fictional sample. Which values are right
    is the protected answer check's question, after the submission on the platform.
    """
    try:
        validate_submission(
            TASK_ROOT / "submission.yaml",
            TASK_ROOT / "docs/contracts/submission.schema.json",
            sample_path=TASK_ROOT / "submission-sample.yaml",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))
