from intent_analysis import IntentAnalysis


def test_normal_google_email_result():
    result = IntentAnalysis(
        agent_directed=False,
        human_directed=True,
        instruction_override=False,
        requests_privileged_action=False,
        sensitive_data_request=False,
        manipulates_agent_behavior=False,
        confidence=0.99,
        reason="Normal human-directed notification.",
    )

    assert result.human_directed is True
    assert result.agent_directed is False
    assert result.instruction_override is False


def test_prompt_injection_result():
    result = IntentAnalysis(
        agent_directed=True,
        human_directed=False,
        instruction_override=True,
        requests_privileged_action=True,
        sensitive_data_request=True,
        manipulates_agent_behavior=True,
        confidence=1.0,
        reason="Attempts to manipulate an AI agent.",
    )

    assert result.agent_directed is True
    assert result.instruction_override is True
    assert result.requests_privileged_action is True


def test_sensitive_data_request_result():
    result = IntentAnalysis(
        agent_directed=True,
        human_directed=False,
        instruction_override=True,
        requests_privileged_action=True,
        sensitive_data_request=True,
        manipulates_agent_behavior=True,
        confidence=1.0,
        reason="Attempts to obtain and exfiltrate sensitive mailbox data.",
    )

    assert result.agent_directed is True
    assert result.instruction_override is True
    assert result.requests_privileged_action is True
    assert result.sensitive_data_request is True