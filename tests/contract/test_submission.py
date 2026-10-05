"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer and path checks for this Task's submission.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.contract.submission_validation import (
    ANSWER_FIELDS,
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
)
from tests.security import pii

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
TEMPLATE = ROOT / "tests/fixtures/submission-template.yaml"
PERMITTED = ["src/worker/use_cases.py", "submission.yaml", "tests/student/test_redaction.py"]
# The two allowed values of `limitation_type`. Every format test that needs a complete
# sheet runs once per value, so this file shows no single type as the example: with two
# allowed values, one example would either be the protected answer or point to it.
LIMITATION_TYPES = ("false_negative", "false_positive")
TYPED = pytest.mark.parametrize("limitation_type", LIMITATION_TYPES)


def valid_answers(limitation_type: str, **overrides: Any) -> dict[str, object]:
    """Return a complete answer sheet in the published shape.

    Fictional format example: these values show the shape and state no result. The note
    is the first entry of the fixture's note list and the limitation the first row of the
    documentation's limitations table, chosen for format alone and not from the redaction
    report; the type is whichever allowed value the calling test runs with, each test
    running once per value. Copying any of this answers nothing.
    """
    answers: dict[str, Any] = {
        "limitation_note": "N-01",
        "limitation_type": limitation_type,
        "documented_limitation": "RL-01",
    }
    answers.update(overrides)
    return {"answers": answers}


def own_answers(limitation_type: str) -> dict[str, object]:
    """Return a complete sheet that is not the published sample, whatever the type.

    The sample is the first entry of each list; the note here is the last supplied note
    id instead, read from the fixture, so the sample-copy check never trips on a sheet
    this file means to be accepted.
    """
    return valid_answers(limitation_type, limitation_note=pii.note_ids(ROOT)[-1])


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


@TYPED
def test_a_complete_sheet_is_well_formed(tmp_path: Path, limitation_type: str) -> None:
    """The public schema accepts a complete sheet without judging its correctness."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(limitation_type)))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_blank_template_fails_with_field_address(tmp_path: Path) -> None:
    """An untouched answer sheet must identify the first incomplete field."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="answers.limitation_note is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"limitation_note": "N-99"}, "limitation_note"),
        ({"limitation_note": "n-01"}, "limitation_note"),
        ({"limitation_type": "missed"}, "limitation_type"),
        ({"limitation_type": "False_Negative"}, "limitation_type"),
        ({"documented_limitation": "RL-99"}, "documented_limitation"),
        ({"documented_limitation": "rl-01"}, "documented_limitation"),
    ],
    ids=[
        "unknown-note",
        "lowercase-note",
        "unlisted-type",
        "capitalised-type",
        "unknown-limitation",
        "lowercase-limitation",
    ],
)
@TYPED
def test_values_outside_the_published_contract_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str, limitation_type: str
) -> None:
    """The public schema must name the field it rejected, and reject the right ones."""
    sheet = valid_answers(limitation_type)
    answers = sheet["answers"]
    assert isinstance(answers, dict)
    answers.update(overrides)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    with pytest.raises(SubmissionError, match=message):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("field", ANSWER_FIELDS)
@TYPED
def test_a_missing_or_blank_field_is_named(
    tmp_path: Path, field: str, limitation_type: str
) -> None:
    """Each of the three answers is required, and a blank one is named as incomplete."""
    answers = dict(valid_answers(limitation_type)["answers"])  # type: ignore[arg-type]
    del answers[field]
    root = _task_root(tmp_path, yaml.safe_dump({"answers": answers}))
    with pytest.raises(SubmissionError, match=field):
        validate_submission(root / "submission.yaml", SCHEMA)

    blank = dict(valid_answers(limitation_type)["answers"])  # type: ignore[arg-type]
    blank[field] = ""
    root = _task_root(tmp_path / "blank", yaml.safe_dump({"answers": blank}))
    with pytest.raises(SubmissionError, match=f"answers.{field} is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "field",
    ["redaction_verified", "instructor_approved", "scan_clean", "notes"],
)
@TYPED
def test_no_self_attestation_or_report_field_is_accepted(
    tmp_path: Path, field: str, limitation_type: str
) -> None:
    """Reject a self-approval, a pass boolean, or a report field."""
    answers = valid_answers(limitation_type)
    mapping = answers["answers"]
    assert isinstance(mapping, dict)
    mapping[field] = True
    root = _task_root(tmp_path, yaml.safe_dump(answers))

    with pytest.raises(SubmissionError, match="Additional properties"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_missing_answers_mapping_is_rejected(tmp_path: Path) -> None:
    """The answers mapping is required, not merely tolerated."""
    root = _task_root(tmp_path, "task: 4.4\n")

    with pytest.raises(SubmissionError, match="answers must be one mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_exact_sample_copy_is_rejected(tmp_path: Path) -> None:
    """The published sample must not be accepted as a student submission."""
    root = _task_root(tmp_path, (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="fictional sample"):
        validate_submission(
            root / "submission.yaml",
            SCHEMA,
            sample_path=root / "submission-sample.yaml",
        )


def test_public_entrypoint_reports_an_incomplete_answer_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch a verifier entrypoint that skips the real submission contract."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=[], format_only=True) == 1
    assert "answers.limitation_note is incomplete" in capsys.readouterr().err


@TYPED
def test_public_entrypoint_rejects_the_sample_and_accepts_a_complete_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], limitation_type: str
) -> None:
    """`poe answers` applies the sample-copy check; a complete sheet of its own passes."""
    copied = _task_root(tmp_path / "copied", (ROOT / "submission-sample.yaml").read_text("utf-8"))
    assert main(copied, changed_paths=[], format_only=True) == 1
    assert "fictional sample" in capsys.readouterr().err

    own = _task_root(tmp_path / "own", yaml.safe_dump(own_answers(limitation_type)))
    assert main(own, changed_paths=[], format_only=True) == 0
    assert main(own, changed_paths=list(PERMITTED)) == 0


@TYPED
def test_public_entrypoint_reports_a_protected_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], limitation_type: str
) -> None:
    """A change to the supplied redactor is named, not silently accepted."""
    root = _task_root(tmp_path, yaml.safe_dump(own_answers(limitation_type)))

    assert main(root, changed_paths=["src/common/redactor.py"]) == 1
    assert "protected path changed: src/common/redactor.py" in capsys.readouterr().err


def test_only_the_three_permitted_paths_may_change() -> None:
    """The worker, the answer sheet, and the student test file; nothing else."""
    validate_changed_paths(list(PERMITTED))

    for protected in (
        "src/common/redactor.py",
        "docs/security/redactor.md",
        "tests/fixtures/pii/notes.yaml",
        "src/adapters/model/deterministic.py",
        "src/adapters/model/request_log.py",
        "src/api/routes.py",
        "src/worker/guardrail.py",
        "src/common/audit.py",
        "schemas/exception-summary.schema.json",
        "config/auth.yaml",
        "tests/security/redaction_mutation.py",
        "tests/contract/test_redaction_contract.py",
        "tests/student/test_output_guardrail.py",
        "tests/student/test_audit.py",
        "tests/student/test_exception_access.py",
        ".github/workflows/task.yml",
        "compose.yaml",
        "pyproject.toml",
        "README.md",
        "submission-sample.yaml",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {value: fictional}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {limitation_note: N-01}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_the_schema_names_exactly_the_supplied_note_and_limitation_ids() -> None:
    """The fixture, the redactor's documentation, and the schema agree on every id."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    answers = schema["properties"]["answers"]["properties"]

    assert tuple(answers["limitation_note"]["enum"]) == pii.note_ids(ROOT)
    assert tuple(answers["documented_limitation"]["enum"]) == pii.limitation_ids(ROOT)
    assert tuple(answers["limitation_type"]["enum"]) == LIMITATION_TYPES
    assert tuple(schema["properties"]["answers"]["required"]) == ANSWER_FIELDS
    assert len(pii.note_ids(ROOT)) >= 6, "at least five notes beside N-01"
    assert len(pii.limitation_ids(ROOT)) >= 4, "at least four documented limitations"


def test_the_template_fixture_is_a_blank_sheet_with_the_three_fields() -> None:
    """The fixture is the blank shape: the three fields, each an empty string."""
    document = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    assert document == {"answers": dict.fromkeys(ANSWER_FIELDS, "")}
