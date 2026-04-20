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
    assert result.verdict == "UNVERIFIED"
    assert result.confidence >= 0.8
    assert result.feedback == "UNVERIFIED（未证实） - 关键证据错误"
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


def test_parse_global_review_json_with_blockers_and_resolved_ids():
    content = '''
    {
      "passed": false,
      "feedback": "EXPORT 跟入仍不足",
      "scores": {
        "export_followthrough": 0.72,
        "report_completeness": 0.88
      },
      "blocking_issues": [
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
    assert result.blocking_issues[0]["id"] == "export-followthrough:send-socket"
    assert result.blocking_issues[0]["target"] == "IPSEC_SOCK_SendToSocket"
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
    assert result.verdict == "REJECT"
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
    assert result.verdict == "REFUTED"
    assert result.feedback == "REFUTED（已证伪） - 该问题已被证伪"
