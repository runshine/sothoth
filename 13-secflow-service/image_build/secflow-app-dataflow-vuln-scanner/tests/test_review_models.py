from app.pi_vuln_core.review.models import parse_review_response


def test_parse_json_with_string_confidence_and_false_positive_verdict():
    content = '''
    {
      "report_id": "result_003.md",
      "verdict": "FALSE_POSITIVE",
      "confidence": "HIGH",
      "summary": "报告声称的数组越界访问漏洞不存在。"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence >= 0.8
    assert result.feedback == "FALSE_POSITIVE（误报） - 报告声称的数组越界访问漏洞不存在。"
    assert result.feedback_detail == "报告声称的数组越界访问漏洞不存在。"


def test_parse_nested_json_with_unverified_verdict():
    content = '''
    {
      "verification_summary": {
        "overall_verdict": "UNVERIFIED - 关键证据错误",
        "confidence_level": "HIGH",
        "recommendation": "驳回"
      },
      "summary": "关键证据错误"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "INSUFFICIENT_INFO"
    assert result.confidence >= 0.8
    assert result.feedback == "INSUFFICIENT_INFO（证据不足） - 关键证据错误"
    assert result.feedback_detail == "关键证据错误"


def test_parse_markdown_false_positive():
    content = '''
    ## 评审完成

    ### 评审结论: **FALSE_POSITIVE** (误报)

    ### 核心发现
    - 漏洞不存在
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FALSE_POSITIVE"
    assert result.feedback == "FALSE_POSITIVE（误报）"
    assert result.feedback_detail == content


def test_parse_markdown_insufficient_info_as_failure():
    content = '''
    评审完成。以下是针对漏洞报告的评审结论摘要：

    ## 评审结论：**INSUFFICIENT_INFO**（证据不足）
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "INSUFFICIENT_INFO"
    assert result.feedback == "INSUFFICIENT_INFO（证据不足）"


def test_parse_simple_pass_json():
    content = '{"passed": true, "feedback": "分析扎实，结论可靠", "confidence": 0.92}'
    result = parse_review_response(content)
    assert result.passed is True
    assert result.verdict == "PASS"
    assert result.feedback == "PASS（通过） - 分析扎实，结论可靠"
    assert result.feedback_detail == "分析扎实，结论可靠"
    assert result.confidence == 0.92


def test_parse_json_without_clear_pass_fail_signal_defaults_to_fail_close():
    content = '{"report_id":"result_002","overall_verdict":"MEDIUM_CONFIDENTION","details":{"a":1}}'
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FAIL"
    assert result.feedback == "FAIL（未通过） - MEDIUM_CONFIDENTION"
    assert result.feedback_detail == "MEDIUM_CONFIDENTION"
    assert result.raw_content == content


def test_parse_global_review_json_with_issues_and_resolved_ids():
    content = '''
    {
      "passed": false,
      "feedback": "EXPORT 跟入仍不足",
      "scores": {
        "export_followthrough": 0.72,
        "report_completeness": 0.88
      },
      "issues": [
        {
          "id": "export-followthrough:send-socket",
          "category": "export_followthrough",
          "target": "IPSEC_SOCK_SendToSocket",
          "severity": "high",
          "required_action": "继续跟入至少两层并给出安全/漏洞结论"
        }
      ],
      "resolved_issues": ["input-coverage:manual-sa"]
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.issues[0]["id"] == "export-followthrough:send-socket"
    assert result.issues[0]["target"] == "IPSEC_SOCK_SendToSocket"
    assert result.resolved_issue_ids == ["input-coverage:manual-sa"]
    assert result.scores["export_followthrough"] == 0.72


def test_parse_result_review_json_prefers_top_level_verdict_over_nested_pass_flags():
    content = '''
    {
      "verdict": "REJECTED",
      "summary": "攻击前提不成立",
      "findings": [
        {"category": "code_evidence", "passed": true},
        {"category": "trigger_conditions", "passed": false}
      ]
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"
    assert "攻击前提不成立" in result.feedback


def test_parse_result_review_json_marks_refuted_and_dismiss_as_failure():
    content = '''
    {
      "verdict": "REFUTED",
      "summary": "该问题已被证伪",
      "recommendation": "DISMISS"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"
    assert result.feedback == "REJECTED（驳回） - 该问题已被证伪"


def test_parse_global_passed_true_is_not_overridden_by_feedback_keywords():
    content = '''
    {
      "passed": true,
      "feedback": "Cycle 10 closure审计通过。最终保留2个独立漏洞报告，删除的6个误报均提供了充分代码证据。",
      "scores": {
        "input_coverage": 1.0,
        "export_followthrough": 1.0,
        "used_coverage": 1.0,
        "vuln_pattern_breadth": 0.95,
        "code_evidence_depth": 0.95,
        "limitations_honesty": 0.95,
        "report_completeness": 1.0
      },
      "issues": [],
      "resolved_issues": ["global-review:summary-or-coverage:cc73d8c745"]
    }
    '''
    result = parse_review_response(content)
    assert result.passed is True
    assert result.verdict == "PASS"
    assert "删除的6个误报" in result.feedback_detail
    assert result.issues == []
    assert result.resolved_issue_ids == ["global-review:summary-or-coverage:cc73d8c745"]


def test_parse_top_level_passed_conflicts_with_explicit_verdict_fail_closes():
    content = '''
    {
      "passed": true,
      "verdict": "REJECTED",
      "feedback": "模型顶层判定与显式 verdict 冲突"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"


def test_parse_partially_valid_is_not_confirmed_true_positive():
    content = '''
    {
      "verdict": "PARTIALLY_VALID",
      "summary": "报告识别了真实安全缺陷，但攻击路径分析不完整。"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"
    assert "攻击路径分析不完整" in result.feedback


def test_parse_true_positive_alias_is_canonicalized_to_confirmed():
    content = '''
    {
      "passed": true,
      "verdict": "TRUE_POSITIVE",
      "summary": "漏洞路径闭环，确认为真阳性"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is True
    assert result.verdict == "CONFIRMED"
    assert result.feedback == "CONFIRMED（已确认） - 漏洞路径闭环，确认为真阳性"


def test_parse_verification_result_alias_partially_valid_preserves_confidence():
    content = '''
    {
      "verification_result": "PARTIALLY_VALID",
      "findings": [
        {
          "description": "边界检查时机错误：ah_header 在边界检查之前就被使用"
        }
      ],
      "confidence": "HIGH"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"
    assert result.confidence >= 0.8
    assert "边界检查时机错误" in result.feedback_detail


def test_parse_json_like_false_positive_with_invalid_numeric_range():
    content = '''
    基于以上源码验证，现在生成JSON验证结果：

    ```json
    {
      "verification_status": "FALSE_POSITIVE",
      "confidence": "HIGH",
      "summary": "该漏洞报告存在多处问题夸大和逻辑错误，实际可利用性极低",
      "findings": [
        {
          "line_number": 26870-26878,
          "description": "边界条件bug而非安全漏洞"
        }
      ]
    }
    ```
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence >= 0.8
    assert "该漏洞报告存在多处问题夸大和逻辑错误" in result.feedback_detail


def test_parse_verification_result_false_positive_alias_and_chinese_sentence():
    content = '''
    {
      "verification_result": "FALSE_POSITIVE",
      "verdict": "该漏洞报告为假阳性，代码实现符合 RFC 标准且具备完整的错误处理链",
      "confidence": "HIGH",
      "summary": "报告声称的'SPI验证不足'实际上是符合 RFC 4302/4303 的正确实现。"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence >= 0.8
    assert "SPI验证不足" in result.feedback_detail


def test_parse_exact_false_verdict_as_false_positive():
    content = '''
    {
      "verdict": "FALSE",
      "confidence": "HIGH",
      "summary": "该漏洞报告的核心攻击场景存在严重事实错误。"
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence >= 0.8


def test_parse_confirmed_with_modifications_nested_final_verdict_as_rejected():
    content = '''
    {
      "verification_result": "CONFIRMED_WITH_MODIFICATIONS",
      "severity_assessment": {
        "rationale": "漏洞确实存在（IV长度未验证≤16），但严重程度评估正确。攻击复杂度高，需要SA配置错误或内部特权操作。"
      },
      "final_verdict": {
        "vulnerability_confirmed": true,
        "severity_correct": true,
        "attack_scenario_invalid": true,
        "data_flow_claim_incorrect": true
      }
    }
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.verdict == "REJECTED"
    assert "漏洞确实存在" in result.feedback_detail
