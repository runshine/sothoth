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
    assert result.confidence >= 0.8
    assert "FALSE_POSITIVE" in result.feedback


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
    assert result.confidence >= 0.8
    assert result.feedback


def test_parse_markdown_false_positive():
    content = '''
    ## 评审完成

    ### 评审结论: **FALSE_POSITIVE** (误报)

    ### 核心发现
    - 漏洞不存在
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.feedback == "FALSE_POSITIVE（误报）"


def test_parse_markdown_insufficient_info_as_failure():
    content = '''
    评审完成。以下是针对漏洞报告的评审结论摘要：

    ## 评审结论：**INSUFFICIENT_INFO**（证据不足）
    '''
    result = parse_review_response(content)
    assert result.passed is False
    assert result.feedback == "INSUFFICIENT_INFO（证据不足）"


def test_parse_simple_pass_json():
    content = '{"passed": true, "feedback": "分析扎实，结论可靠", "confidence": 0.92}'
    result = parse_review_response(content)
    assert result.passed is True
    assert result.feedback == "分析扎实，结论可靠"
    assert result.confidence == 0.92
