from app.pi_vuln_core.review.state import ReviewState


def test_blocker_backlog_carries_forward_until_explicitly_resolved():
    state = ReviewState()

    state.record_global_review_result(
        cycle=1,
        passed=False,
        feedback="初次发现两个 blocker",
        scores={"export_followthrough": 0.6},
        blocking_issues=[
            {
                "id": "export:send-socket",
                "category": "export_followthrough",
                "target": "IPSEC_SOCK_SendToSocket",
                "severity": "high",
                "required_action": "继续跟入 send socket 链",
            },
            {
                "id": "limitations:section-7",
                "category": "limitations_honesty",
                "target": "summary.md#7",
                "severity": "high",
                "required_action": "补全局限性章节",
            },
        ],
        resolved_issue_ids=[],
    )
    assert state.get_open_blocker_ids() == [
        "export:send-socket",
        "limitations:section-7",
    ]

    # 第二轮静默省略了第一个 blocker，但没有显式 resolved —— 必须继续保留。
    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="局限性章节仍未修好",
        scores={"export_followthrough": 0.6},
        blocking_issues=[
            {
                "id": "limitations:section-7",
                "category": "limitations_honesty",
                "target": "summary.md#7",
                "severity": "high",
                "required_action": "补全局限性章节",
            },
        ],
        resolved_issue_ids=[],
    )
    assert state.get_open_blocker_ids() == [
        "export:send-socket",
        "limitations:section-7",
    ]

    # 第三轮显式声明第一个 blocker 已解决，才允许关闭。
    state.record_global_review_result(
        cycle=3,
        passed=False,
        feedback="只剩一个 blocker",
        scores={"export_followthrough": 0.8},
        blocking_issues=[
            {
                "id": "limitations:section-7",
                "category": "limitations_honesty",
                "target": "summary.md#7",
                "severity": "high",
                "required_action": "补全局限性章节",
            },
        ],
        resolved_issue_ids=["export:send-socket"],
    )
    assert state.get_open_blocker_ids() == ["limitations:section-7"]

    # 最终通过后，所有 blocker 自动清空。
    state.record_global_review_result(
        cycle=4,
        passed=True,
        feedback="全局评审通过",
        scores={"export_followthrough": 1.0},
        blocking_issues=[],
        resolved_issue_ids=[],
    )
    assert state.get_open_blockers() == []


def test_state_has_failures_only_tracks_current_unresolved_items():
    state = ReviewState()
    state.mark_result_failed("result_999.md", 1, "stale deleted result")
    state.record_global_failure(1, "old global fail")

    assert state.has_failures() is True
    assert state.has_failures(current_results=["result_001.md"], actionable_by="worker") is False

    state.record_global_review_result(
        cycle=2,
        passed=False,
        feedback="framework metadata sync",
        scores={"report_completeness": 0.5},
        blocking_issues=[
            {
                "id": "framework-sync",
                "category": "report_completeness",
                "target": "open_blockers.json",
                "severity": "high",
                "required_action": "同步 open_blockers.json",
                "actionable_by": "framework",
            }
        ],
        resolved_issue_ids=[],
    )

    assert state.has_failures(current_results=["result_001.md"], actionable_by="worker") is False
    assert state.has_failures(current_results=["result_001.md"], actionable_by="framework") is True

    state.record_global_review_result(
        cycle=3,
        passed=True,
        feedback="pass",
        scores={"report_completeness": 1.0},
        blocking_issues=[],
        resolved_issue_ids=[],
    )
    feedback = state.format_failure_feedback(
        current_results=["result_001.md"],
        include_open_blockers=False,
        include_global_feedback_section=True,
    )
    assert "最近一次全局评审反馈" not in feedback
