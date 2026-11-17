import pytest

from agentguard import (
    AuditLog,
    CircuitBreaker,
    HoneyTokenRegistry,
    Limit,
    PolicyEnforcementPoint,
    RevocationBus,
    TokenBroker,
    TokenError,
    ToolCall,
)


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


AGENT = "spiffe://test/agent/a"


@pytest.fixture
def env():
    clock = Clock()
    broker = TokenBroker(key=b"k" * 32, clock=clock)
    bus = RevocationBus()
    audit = AuditLog(clock=clock)
    honey = HoneyTokenRegistry()
    breaker = CircuitBreaker(
        [
            Limit("rows_deleted", per_action=10),
            Limit("funds", per_action=500, window_total=1000, window_seconds=3600),
        ],
        clock=clock,
    )
    pep = PolicyEnforcementPoint(broker, bus, breaker, honey, audit)
    token = broker.mint(
        AGENT, "t1", {"read", "send_email", "delete_record", "pay"},
        methods={"GET", "POST", "DELETE"}, max_egress_bytes=1000, ttl=120,
    )
    return dict(clock=clock, broker=broker, bus=bus, audit=audit, honey=honey,
                breaker=breaker, pep=pep, token=token)


# ---- capability tokens ----

def test_ttl_bounds_enforced(env):
    with pytest.raises(TokenError):
        env["broker"].mint(AGENT, "t", {"read"}, ttl=30)
    with pytest.raises(TokenError):
        env["broker"].mint(AGENT, "t", {"read"}, ttl=3600)


def test_token_needs_tools(env):
    with pytest.raises(TokenError):
        env["broker"].mint(AGENT, "t", set())


def test_token_roundtrip_and_expiry(env):
    cap = env["broker"].verify(env["token"])
    assert cap.subject == AGENT and "read" in cap.tools
    env["clock"].t += 121
    with pytest.raises(TokenError, match="expired"):
        env["broker"].verify(env["token"])


def test_forged_token_rejected(env):
    other = TokenBroker(key=b"x" * 32, clock=env["clock"])
    forged = other.mint(AGENT, "t", {"pay"})
    with pytest.raises(TokenError, match="signature"):
        env["broker"].verify(forged)
    with pytest.raises(TokenError, match="malformed"):
        env["broker"].verify("nonsense")


def test_tampered_claims_rejected(env):
    body, sig = env["token"].split(".")
    tampered = body[:-2] + ("AA" if body[-2:] != "AA" else "BB")
    with pytest.raises(TokenError):
        env["broker"].verify(f"{tampered}.{sig}")


# ---- PEP ----

def test_allowed_read(env):
    assert env["pep"].authorize(env["token"], ToolCall("read")).allowed


def test_tool_outside_capability(env):
    d = env["pep"].authorize(env["token"], ToolCall("read_payroll"))
    assert not d.allowed and "not in capability" in d.reason


def test_method_outside_capability(env):
    d = env["pep"].authorize(env["token"], ToolCall("read", "PUT"))
    assert not d.allowed and "method" in d.reason


@pytest.mark.parametrize("source", ["tool_output", "retrieved_document"])
def test_untrusted_source_cannot_trigger_side_effects(env, source):
    call = ToolCall("send_email", "POST", instruction_source=source, human_approval="human:a")
    d = env["pep"].authorize(env["token"], call)
    assert not d.allowed and "untrusted" in d.reason


def test_untrusted_source_may_still_read(env):
    call = ToolCall("read", instruction_source="retrieved_document")
    assert env["pep"].authorize(env["token"], call).allowed


def test_irreversible_needs_human(env):
    d = env["pep"].authorize(env["token"], ToolCall("send_email", "POST"))
    assert not d.allowed and "human approval" in d.reason
    d = env["pep"].authorize(env["token"], ToolCall("send_email", "POST", human_approval="bot:x"))
    assert not d.allowed
    d = env["pep"].authorize(env["token"], ToolCall("send_email", "POST", human_approval="human:alice"))
    assert d.allowed


def test_egress_cap(env):
    d = env["pep"].authorize(env["token"], ToolCall("read", egress_bytes=5000))
    assert not d.allowed and "egress" in d.reason


def test_honeytoken_kills_agent(env):
    decoy = env["honey"].plant("rag:test")
    d = env["pep"].authorize(env["token"], ToolCall("read", args={"k": f"x {decoy.value} y"}))
    assert not d.allowed and "honey-token" in d.reason
    # every later call is denied, even a fresh token for the same agent
    assert not env["pep"].authorize(env["token"], ToolCall("read")).allowed
    fresh = env["broker"].mint(AGENT, "t2", {"read"})
    assert "revoked" in env["pep"].authorize(fresh, ToolCall("read")).reason


def test_revoke_single_token(env):
    jti = env["broker"].verify(env["token"]).jti
    env["bus"].revoke_token(jti, "test")
    assert not env["pep"].authorize(env["token"], ToolCall("read")).allowed
    fresh = env["broker"].mint(AGENT, "t2", {"read"})
    assert env["pep"].authorize(fresh, ToolCall("read")).allowed


def test_breaker_per_action_cap(env):
    call = ToolCall("delete_record", "DELETE", metrics={"rows_deleted": 11}, human_approval="human:a")
    d = env["pep"].authorize(env["token"], call)
    assert not d.allowed and "circuit breaker" in d.reason


def test_breaker_window_budget_and_expiry(env):
    pay = lambda amt: ToolCall("pay", "POST", metrics={"funds": amt})
    assert env["pep"].authorize(env["token"], pay(500)).allowed
    assert env["pep"].authorize(env["token"], pay(500)).allowed
    assert not env["pep"].authorize(env["token"], pay(1)).allowed
    env["clock"].t += 3601
    fresh = env["broker"].mint(AGENT, "t2", {"pay"}, methods={"POST"})
    assert env["pep"].authorize(fresh, pay(500)).allowed


def test_breaker_rejects_negative_amounts():
    br = CircuitBreaker([Limit("funds", window_total=100)])
    assert not br.check("s", {"funds": -1000}).allowed


def test_denied_action_does_not_consume_budget():
    br = CircuitBreaker([Limit("funds", per_action=50, window_total=100)])
    assert not br.check("s", {"funds": 80}).allowed
    assert br.check("s", {"funds": 50}).allowed
    assert br.check("s", {"funds": 50}).allowed


# ---- audit ----

def test_every_decision_audited_and_chain_verifies(env):
    env["pep"].authorize(env["token"], ToolCall("read"))
    env["pep"].authorize(env["token"], ToolCall("nope"))
    recs = env["audit"].records()
    assert [r["allowed"] for r in recs] == [True, False]
    assert env["audit"].verify()


def test_audit_detects_tampering(env):
    env["pep"].authorize(env["token"], ToolCall("read"))
    env["pep"].authorize(env["token"], ToolCall("read"))
    env["audit"]._records[0]["allowed"] = False
    assert not env["audit"].verify()


def test_audit_detects_deletion(env):
    for _ in range(3):
        env["pep"].authorize(env["token"], ToolCall("read"))
    del env["audit"]._records[1]
    assert not env["audit"].verify()


def test_audit_omits_arguments(env):
    env["pep"].authorize(env["token"], ToolCall("read", args={"secret": "s3cr3t"}))
    assert "s3cr3t" not in str(env["audit"].records())


def test_demo_runs(capsys):
    from agentguard.demo import main
    main()
    out = capsys.readouterr().out
    assert "chain intact: True" in out
    assert out.count("[ALLOW]") == 2


@pytest.mark.parametrize("source", ["", "User", "web"])
def test_unknown_source_fails_closed(env, source):
    call = ToolCall("send_email", "POST", instruction_source=source, human_approval="human:a")
    assert not env["pep"].authorize(env["token"], call).allowed
