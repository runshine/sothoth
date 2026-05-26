# Handoff Prompt: Review-Driven Multi-Agent Vulnerability Discovery

You are implementing or documenting a review-driven, multi-round, multi-agent vulnerability discovery system. You do not need any prior conversation context. The user asked for an independent design and explicitly said not to read project files. Therefore, do not assume repository-specific implementation details unless you inspect them in a later non-plan phase with permission.

## Goal
Design a system that takes as input:
1. A module's source code.
2. A data-flow / taint-analysis file starting from the module entry function.

The system must use multiple agents to find vulnerabilities more comprehensively and more deeply than a single-agent audit. It must reduce false negatives without falling into unproductive repeated rounds.

## Required Agents
1. **Worker / Vulnerability Discovery Agent**
   - Performs the actual audit.
   - Receives concrete task cards from the orchestrator.
   - Outputs candidate vulnerabilities and evidence.

2. **Comprehensiveness Review Agent**
   - Evaluates whether the audit has covered all relevant attack surfaces, sources, sinks, taint paths, vulnerability classes, and security boundaries.
   - Produces next-round directions focused on breadth and missing coverage.

3. **Depth Review Agent**
   - Evaluates whether the audit is too shallow.
   - Produces next-round directions focused on complex paths, constraints, sanitizer bypasses, state machines, implicit flows, and vulnerability chains.

4. **False Positive Review Agent**
   - Reviews newly added candidate vulnerabilities.
   - Maintains vulnerability result states together with the Worker:
     - `待结果评审` / pending result review
     - `确认是漏洞` / confirmed vulnerability
     - `确认为误报` / confirmed false positive
     - Recommended additional state: `需要补充证据` / needs more evidence

5. **Programmatic Orchestrator**
   - Controls rounds, budgets, task generation, stop decisions, context compression, and state updates.
   - LLM agents may recommend stopping, but the final stop decision must be programmatic for reproducibility and cost control.

## Core State Models
Implement or specify these conceptual structures:

### AuditState
Tracks the whole audit:
- Module metadata.
- Entry functions.
- Code summaries.
- Taint graph summaries.
- Call graph.
- Source/sink inventory.
- Security boundaries.
- Candidate vulnerability list.
- Confirmed vulnerabilities.
- False positives.
- Per-round task cards, findings, and review feedback.

### ExplorationLedger
Prevents repeated empty work:
- Each exploration task has a fingerprint: scope + taint path + vulnerability class + hypothesis.
- Track whether it was attempted, completed, yielded results, failed, or needs decomposition.
- Reject near-duplicate tasks unless they include new evidence objectives.

### CoverageMatrix
Measures breadth:
- Entry coverage.
- Source coverage.
- Sink coverage.
- Source-sink pair coverage.
- Taint-path coverage.
- Function/file coverage.
- Vulnerability-class coverage.
- Security-boundary coverage.
- Error/exception/default-path coverage.

### DepthMatrix
Measures depth:
- Interprocedural depth.
- Cross-file/cross-object depth.
- Alias/pointer/object-field tracking.
- Constraint and branch-condition analysis.
- State-machine and temporal analysis.
- Sanitizer/filter semantic verification.
- Implicit and secondary flows.
- Exploit-chain or vulnerability-composition analysis.

## Workflow Plan
Mark each completed step with `[DONE:n]` during implementation or documentation.

1. [ ] Define the structured result schema for candidate vulnerabilities.
   - Fields: ID, round, status, vulnerability class, source, sink, taint path, code location, trigger conditions, attacker capability, impact, evidence, confidence, review notes, related task card.
   - Include `需要补充证据` in addition to pending/confirmed/false-positive states.

2. [ ] Define the `TaskCard` schema consumed by the Worker.
   - Fields: task ID, round, objective, scope, taint paths, source/sink pairs, vulnerability classes, hypothesis, required evidence, out-of-scope areas, expected output, budget.
   - Make tasks concrete and non-generic.

3. [ ] Specify Worker behavior.
   - Worker must execute task cards rather than perform unconstrained repeated audits.
   - Worker output must include complete evidence for each finding: source-to-sink path, control/data constraints, sanitizer behavior, impact, exploitability assumptions, uncertainty.
   - Worker may report side findings, but main focus must remain the task card.
   - After implementing/documenting this, mark `[DONE:3]`.

4. [ ] Specify Comprehensiveness Review Agent behavior.
   - It must answer: “What important parts of the attack surface have not been examined?”
   - Evaluate:
     - Entry points.
     - Sources.
     - Sinks.
     - Source-sink pairs.
     - Taint paths.
     - Vulnerability classes.
     - Security boundaries.
     - Error/default/exception paths.
   - It must output:
     - Coverage matrix updates.
     - Top missing coverage gaps.
     - Risk reason for each gap.
     - Concrete next-round task cards.
   - It must not output generic advice.
   - After implementing/documenting this, mark `[DONE:4]`.

5. [ ] Specify Depth Review Agent behavior.
   - It must answer: “Where is the current audit shallow, under-proven, or likely to miss complex vulnerabilities?”
   - Evaluate:
     - Interprocedural and cross-file path depth.
     - Branch/constraint conditions.
     - State-machine and temporal dependencies.
     - Implicit flows and second-order flows.
     - Sanitizer/filter bypasses.
     - Parser differentials, normalization issues, type conversions, encoding issues.
     - Vulnerability chains.
   - It must output:
     - Shallow conclusions.
     - Findings requiring more evidence.
     - Deep-dive hypotheses.
     - Concrete next-round task cards.
     - Reasons why further deep-dive is or is not worthwhile.
   - After implementing/documenting this, mark `[DONE:5]`.

6. [ ] Specify False Positive Review Agent behavior.
   - Review only newly added or newly supplemented findings each round.
   - Distinguish between:
     - Proven false positive.
     - Real vulnerability.
     - Insufficient evidence.
   - For insufficient evidence, generate a supplemental evidence request that can become a Depth Review task.
   - After implementing/documenting this, mark `[DONE:6]`.

7. [ ] Specify the Orchestrator loop.
   - Round 0: parse/summarize inputs, build initial source/sink/path inventory, initialize CoverageMatrix and DepthMatrix.
   - Round 1: generate baseline high-risk task cards.
   - Each round:
     1. Send task cards to Worker.
     2. Collect new candidate vulnerabilities.
     3. Run false positive review on new/supplemented findings.
     4. Run comprehensiveness review.
     5. Run depth review.
     6. Merge review outputs into prioritized next-round tasks.
     7. Update ledgers and matrices.
     8. Decide whether to stop.
   - After implementing/documenting this, mark `[DONE:7]`.

8. [ ] Define task prioritization.
   - Suggested formula:
     `priority = (risk_weight * (coverage_gap + depth_gap) * novelty * expected_yield) / estimated_cost`
   - Components:
     - `risk_weight`: sink severity, exposed attack surface, privilege boundary.
     - `coverage_gap`: missing breadth coverage.
     - `depth_gap`: shallow or unproven reasoning.
     - `novelty`: dissimilarity from previous tasks.
     - `expected_yield`: estimated chance of finding a meaningful vulnerability.
     - `estimated_cost`: code size, path complexity, token/time cost.
   - After implementing/documenting this, mark `[DONE:8]`.

9. [ ] Define anti-stagnation controls.
   - Deduplicate task cards by fingerprint.
   - Reject generic review feedback.
   - Downgrade directions that produce no new evidence for multiple rounds.
   - Limit retries per direction and per vulnerability class.
   - Require every repeated task to introduce a new hypothesis or evidence target.
   - Track marginal yield over recent rounds.
   - After implementing/documenting this, mark `[DONE:9]`.

10. [ ] Define stopping logic.
    - Final stopping must be controlled by programmatic Orchestrator, not solely by an LLM.
    - Hard stops:
      - Maximum rounds reached.
      - Token/time/cost budget exhausted.
      - No executable task cards remain.
      - Required high-risk coverage targets reached.
    - Soft stops:
      - Consecutive rounds with no confirmed vulnerabilities.
      - Candidate confirmation rate below threshold.
      - High-risk path coverage above threshold, e.g. > 90%.
      - Depth coverage above threshold.
      - Next-round expected yield below cost threshold.
    - Suggested combined rule:
      - Continue if there exists a task with `priority >= P_min`, budget remains, and recent marginal yield is acceptable.
      - Stop if budget is exhausted, or if `coverage_score >= C_min` and `depth_score >= D_min` and `marginal_yield < Y_min` for `R` consecutive rounds.
    - After implementing/documenting this, mark `[DONE:10]`.

11. [ ] Define final report structure.
    - Confirmed vulnerabilities with evidence and remediation.
    - False positives and reasons.
    - Findings needing more evidence, if stopped due to budget.
    - Coverage matrix and depth matrix.
    - Uncovered residual risks.
    - Stop reason and resource usage.
    - Do not claim the module is fully safe; state residual risk explicitly.
    - After implementing/documenting this, mark `[DONE:11]`.

## Critical Design Principles
- Comprehensiveness review is about “where have we not looked?”
- Depth review is about “where did we look too shallowly?”
- False positive review is about “is this reported issue real?”
- The Worker should not be asked to “audit again” generically; it should receive narrow, concrete, high-yield task cards.
- The system’s advantage over a single agent comes from persistent state, coverage/depth metrics, structured critique, deduplication, and programmatic round control.
- The stopping decision should be hybrid: LLMs provide qualitative evidence and suggestions; code enforces deterministic thresholds.

## Gotchas
- Do not treat the taint-analysis file as complete truth. It may miss implicit flows, second-order flows, or framework-specific sources/sinks.
- Avoid generic suggestions like “check authentication” unless tied to a concrete function/path/boundary.
- Avoid premature false-positive marking when evidence is merely incomplete; use “needs more evidence”.
- Avoid infinite rounds by tracking novelty and marginal yield.
- Make every next-round task measurable: if a task cannot be verified as completed, it is too vague.
