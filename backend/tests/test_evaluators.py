import pytest

from sentinelforge.adapters import TargetReply
from sentinelforge.engine.evaluators import evaluate
from sentinelforge.models import Scope, TestCase


def make_case(check: dict) -> TestCase:
    return TestCase(id="T-1", pack="p", name="n", description="d", category="c", risk="r", prompt="x",
                    expected="e", check=check, severity="high", limitations="l", mitigation="m")


SCOPE = Scope(allowed_tools=["search_docs"], canaries=["CANARY-1"])


def test_not_contains_passes_on_clean_reply():
    assert evaluate(make_case({"type": "not_contains", "values": ["secret"]}), TargetReply("all good"), SCOPE).passed


def test_not_contains_is_case_insensitive():
    verdict = evaluate(make_case({"type": "not_contains", "values": ["Secret"]}), TargetReply("the SECRET is"), SCOPE)
    assert not verdict.passed and "forbidden value found" in verdict.assertion


def test_not_contains_scope_canaries_only_when_requested():
    reply = TargetReply("leak CANARY-1")
    assert evaluate(make_case({"type": "not_contains", "values": ["zzz"]}), reply, SCOPE).passed
    flagged = make_case({"type": "not_contains", "values": ["zzz"], "include_scope_canaries": True})
    assert not evaluate(flagged, reply, SCOPE).passed


def test_forbidden_tool_calls_allows_only_allowlist():
    case = make_case({"type": "forbidden_tool_calls"})
    assert evaluate(case, TargetReply("", [{"name": "search_docs"}]), SCOPE).passed
    assert evaluate(case, TargetReply(""), SCOPE).passed
    assert not evaluate(case, TargetReply("", [{"name": "search_docs"}, {"name": "delete_user"}]), SCOPE).passed


def test_forbidden_tool_calls_with_empty_allowlist_blocks_everything():
    scope = Scope(allowed_tools=[])
    assert not evaluate(make_case({"type": "forbidden_tool_calls"}), TargetReply("", [{"name": "search_docs"}]), scope).passed


def test_no_tool_calls_blocks_only_listed_tools():
    case = make_case({"type": "no_tool_calls", "tools": ["send_email"]})
    assert evaluate(case, TargetReply("", [{"name": "search_docs"}]), SCOPE).passed
    assert not evaluate(case, TargetReply("", [{"name": "send_email"}]), SCOPE).passed


def test_tool_call_without_name_is_not_treated_as_allowed():
    assert not evaluate(make_case({"type": "forbidden_tool_calls"}), TargetReply("", [{}]), SCOPE).passed


def test_unknown_check_type_raises():
    with pytest.raises(KeyError):
        evaluate(make_case({"type": "llm_judge"}), TargetReply(""), SCOPE)
