/* ═══════════════════════════════════════════════════
   Vuln Scan Dashboard — Application Logic
   ═══════════════════════════════════════════════════ */

const App = {
  runs: [],
  currentRun: null,
  currentRunData: null,
  currentFiles: [],
  refreshTimer: null,
  REFRESH_INTERVAL: 6000,
  currentRunsFilter: '',
  collapsedRunDates: {},
  runDetailRequestSeq: 0,

  // ── Init ──────────────────────────────────────
  async init() {
    await this.loadRuns();
    this.startAutoRefresh();
  },

  startAutoRefresh() {
    clearInterval(this.refreshTimer);
    this.refreshTimer = setInterval(() => {
      if (document.getElementById('autoRefresh').checked) this.refresh();
    }, this.REFRESH_INTERVAL);
  },

  async refresh() {
    await this.loadRuns();
    if (this.currentRun) await this.loadRunDetail(this.currentRun, true);
  },

  getActiveTab() {
    return document.querySelector('.tab.active[data-tab]')?.dataset.tab || 'overview';
  },

  refreshActiveTabContent() {
    const activeTab = this.getActiveTab();
    if (activeTab === 'sessions') this.loadSessions();
    if (activeTab === 'files') this.loadFiles();
    if (activeTab === 'log') this.loadLog();
  },

  // ── Runs list ─────────────────────────────────
  async loadRuns() {
    try {
      const resp = await fetch('/api/runs');
      this.runs = await resp.json();
      this.filterRuns(this.currentRunsFilter);
    } catch (e) { console.error('loadRuns failed', e); }
  },

  _groupRunsByDate(runs) {
    const groups = [];
    let current = null;
    runs.forEach(r => {
      const dateLabel = this.runDateLabel(r);
      if (!current || current.dateLabel !== dateLabel) {
        current = { dateLabel, runs: [] };
        groups.push(current);
      }
      current.runs.push(r);
    });
    return groups;
  },

  renderRunsList(runs) {
    const el = document.getElementById('runsList');
    if (!runs.length) { el.innerHTML = '<div class="empty-state">暂无运行记录</div>'; return; }

    const groups = this._groupRunsByDate(runs);
    const forceExpanded = !!this.currentRunsFilter;
    el.innerHTML = groups.map(group => {
      const dateKey = group.dateLabel;
      const collapsed = !forceExpanded && !!this.collapsedRunDates[dateKey];
      const arrow = collapsed ? '▶' : '▼';
      const runsHtml = group.runs.map(r => {
        const timeLabel = (r.start_time || '').split(' ')[1] || '--:--:--';
        return `
          <div class="run-item ${this.currentRun === r.name ? 'active' : ''}"
               data-run="${this.attr(r.name)}"
               onclick="App.selectRun(this.dataset.run, event)">
            <div class="run-item-header">
              <span class="run-item-name" title="${this.esc(r.name)}">${this.esc(this.shortName(r.name))}</span>
              ${this.statusBadge(r.status, 'badge-sm')}
            </div>
            <div class="run-item-time">🕒 ${this.esc(timeLabel)}</div>
            <div class="run-item-stats">
              <span>🔄 ${r.cycles_used}/${r.max_cycles}</span>
              <span>✅ ${r.passed_count}</span>
              <span>❌ ${r.failed_count}</span>
              <span>⏳ ${this.fmtDuration(this._estimateDuration(r))}</span>
              <span class="text-muted">${this.esc((r.model || '').split('/').pop())}</span>
            </div>
          </div>
        `;
      }).join('');
      return `
        <div class="run-date-group ${collapsed ? 'collapsed' : ''}">
          <button class="run-date-header" data-date-key="${this.attr(dateKey)}" onclick="App.toggleRunDateGroup(this.dataset.dateKey)">
            <span class="run-date-arrow">${arrow}</span>
            <span class="run-date-label">${this.esc(dateKey)}</span>
            <span class="run-date-count">${group.runs.length}</span>
          </button>
          <div class="run-date-body" style="display:${collapsed ? 'none' : 'block'}">
            ${runsHtml}
          </div>
        </div>
      `;
    }).join('');
  },

  toggleRunDateGroup(dateKey) {
    this.collapsedRunDates[dateKey] = !this.collapsedRunDates[dateKey];
    this.filterRuns(this.currentRunsFilter);
  },

  filterRuns(query) {
    this.currentRunsFilter = String(query || '');
    const q = this.currentRunsFilter.toLowerCase();
    const filtered = this.runs.filter(r => r.name.toLowerCase().includes(q));
    this.renderRunsList(filtered);
  },

  shortName(name) {
    // Trim timestamp suffix for display
    return name.replace(/_\d{8}_\d{6}$/, '').replace(/_/g, ' ');
  },

  runDateLabel(run) {
    if (run.start_date) return run.start_date;
    if (run.start_time) return String(run.start_time).split(' ')[0];
    const name = run.name || '';
    const m = name.match(/(\d{8})_(\d{6})/) || name.match(/(\d{4})[-_]?(\d{2})[-_]?(\d{2})/);
    if (m) {
      if (m[1] && m[1].length === 8) {
        return `${m[1].slice(0,4)}-${m[1].slice(4,6)}-${m[1].slice(6,8)}`;
      }
      return `${m[1]}-${m[2]}-${m[3]}`;
    }
    return '未解析日期';
  },

  async selectRun(name, ev) {
    this.currentRun = name;
    document.querySelectorAll('.run-item').forEach(el => el.classList.remove('active'));
    ev?.target?.closest('.run-item')?.classList.add('active');
    await this.loadRunDetail(name);
  },

  // ── Run detail ────────────────────────────────
  async loadRunDetail(name, silent = false) {
    const requestSeq = ++this.runDetailRequestSeq;
    try {
      const resp = await fetch(this.runApi(name));
      const data = await resp.json();
      if (requestSeq !== this.runDetailRequestSeq || this.currentRun !== name) return;
      this.currentRunData = data;
      this.renderRunDetail(data);
      document.getElementById('welcomeView').style.display = 'none';
      document.getElementById('runDetail').style.display = 'block';
      this.refreshActiveTabContent();
    } catch (e) { if (!silent) console.error('loadRunDetail failed', e); }
  },

  renderRunDetail(data) {
    document.getElementById('runName').textContent = data.name;
    const statusEl = document.getElementById('runStatus');
    statusEl.className = `badge badge-${data.status}`;
    statusEl.textContent = data.status;
    const modeEl = document.getElementById('runMode');
    const lastCycle = data.cycles[data.cycles.length - 1];
    const mode = lastCycle?.workflow_mode || '';
    modeEl.textContent = mode;
    modeEl.style.display = mode ? '' : 'none';

    const c = data.config;
    const advisorCount = (c.global_review_advisors || []).length;
    document.getElementById('runMeta').innerHTML = `
      <span>🤖 ${this.esc(c.model)}</span>
      <span>🧠 ${this.esc(c.thinking)}</span>
      <span>🔄 ${data.cycles_used || data.cycles.length} cycles</span>
      <span>⏱️ ${c.timeout_seconds}s</span>
      <span>🎯 ${c.parallel_result_review ? '并行结果评审' : '串行结果评审'}${c.parallel_result_review_limit ? ` ×${c.parallel_result_review_limit}` : ''}</span>
      ${advisorCount ? `<span>🧩 全局参谋 ${advisorCount}</span>` : ''}
      <span class="run-duration" id="runDuration">⏳ ${this.fmtDuration(this._estimateDuration(data))}</span>
      ${data.error ? `<span class="text-error">⚠️ ${this.esc(data.error).substring(0, 80)}</span>` : ''}
    `;
    // If running, start a live duration timer
    this._startDurationTimer(data.status === 'running');

    this.renderOverview(data);
    this.renderCycles(data);
    this.renderResults(data);
  },

  // ── Overview tab ──────────────────────────────
  renderOverview(data) {
    this.renderScoreChart(data.cycles);
    this.renderIssuesCard(data.latest_issues);
    this.renderManifestCard(data.manifests, data.config);
    this.renderCycleTimeline(data.cycles);
  },

  renderManifestCard(manifests, config) {
    const el = document.getElementById('manifestCard');
    if (!el) return;
    const m = manifests || {};
    const advisors = (config?.global_review_advisors || []).map(a => {
      const fields = (a.score_fields || []).join(', ');
      return `<div class="manifest-advisor"><span class="mono">${this.esc(a.instance_id)}</span><span>${this.esc(fields || '-')}</span></div>`;
    }).join('');
    const manifestLinks = [
      ['result_relations_manifest', '结果关系'],
      ['results_manifest', '结果生命周期'],
    ].map(([key, label]) => {
      const item = m[key] || {};
      const cls = item.exists ? 'text-success' : 'text-muted';
      return item.exists
        ? `<span class="action-link" data-run="${this.attr(this.currentRun)}" data-path="${this.attr(item.path)}" onclick="App.openFile(this.dataset.run, this.dataset.path)">${label}</span>`
        : `<span class="${cls}">${label}: 缺失</span>`;
    }).join('');
    el.innerHTML = `
      <div class="card-title">框架产物一致性</div>
      <div class="manifest-grid">
        <div><span class="metric-num">${m.taskable_result_count ?? 0}</span><span class="text-muted">taskable</span></div>
        <div><span class="metric-num">${m.supplemental_result_count ?? 0}</span><span class="text-muted">supplement</span></div>
        <div><span class="metric-num">${m.inactive_result_count ?? 0}</span><span class="text-muted">inactive</span></div>
        <div><span class="metric-num">${m.excluded_result_count ?? 0}</span><span class="text-muted">excluded</span></div>
      </div>
      <div class="manifest-links">${manifestLinks}</div>
      ${advisors ? `<div class="manifest-advisors">${advisors}</div>` : ''}
    `;
  },

  renderScoreChart(cycles) {
    const el = document.getElementById('scoreChart');
    if (!cycles.length) { el.innerHTML = '<div class="card-title">分数趋势</div><div class="empty-state">暂无数据</div>'; return; }

    const scoreKeys = [...new Set(cycles.flatMap(c => Object.keys(c?.scores || {})))];
    if (!scoreKeys.length) { el.innerHTML = '<div class="card-title">分数趋势</div><div class="empty-state">暂无分数数据</div>'; return; }

    const colors = ['#7aa2f7','#9ece6a','#e0af68','#f7768e','#7dcfff','#bb9af7','#ff9e64'];
    const W = 500, H = 220, PAD = 40, PADR = 20, PADT = 30, PADB = 30;
    const chartW = W - PAD - PADR, chartH = H - PADT - PADB;
    const n = cycles.length;
    const xStep = n > 1 ? chartW / (n - 1) : chartW;

    let svg = `<svg viewBox="0 0 ${W} ${H}" style="width:100%;max-width:${W}px">`;
    // Grid lines
    for (let v = 0; v <= 1; v += 0.25) {
      const y = PADT + chartH * (1 - v);
      svg += `<line x1="${PAD}" y1="${y}" x2="${W-PADR}" y2="${y}" stroke="#3b4261" stroke-width="0.5"/>`;
      svg += `<text x="${PAD-4}" y="${y+4}" text-anchor="end" fill="#565f89" font-size="10">${v.toFixed(2)}</text>`;
    }
    // X labels
    cycles.forEach((c, i) => {
      const x = PAD + (n > 1 ? i * xStep : chartW / 2);
      svg += `<text x="${x}" y="${H-6}" text-anchor="middle" fill="#565f89" font-size="10">C${c.cycle}</text>`;
    });
    // Lines
    scoreKeys.forEach((key, ki) => {
      const color = colors[ki % colors.length];
      const points = cycles.map((c, i) => {
        const x = PAD + (n > 1 ? i * xStep : chartW / 2);
        const v = Number(c.scores?.[key] ?? 0);
        const y = PADT + chartH * (1 - v);
        return `${x},${y}`;
      });
      svg += `<polyline points="${points.join(' ')}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/>`;
      // Dots
      cycles.forEach((c, i) => {
        const x = PAD + (n > 1 ? i * xStep : chartW / 2);
        const v = Number(c.scores?.[key] ?? 0);
        const y = PADT + chartH * (1 - v);
        svg += `<circle cx="${x}" cy="${y}" r="3" fill="${color}"><title>${key}: ${v.toFixed(2)} (Cycle ${c.cycle})</title></circle>`;
      });
    });
    svg += '</svg>';

    // Legend
    const legend = scoreKeys.map((key, ki) =>
      `<span style="display:inline-flex;align-items:center;gap:4px;margin-right:12px;font-size:11px">` +
      `<span style="width:10px;height:3px;background:${colors[ki % colors.length]};border-radius:2px;display:inline-block"></span>` +
      `${key}</span>`
    ).join('');

    el.innerHTML = `<div class="card-title">分数趋势</div><div class="score-chart">${svg}</div><div style="margin-top:8px">${legend}</div>`;
  },

  renderIssuesCard(issues) {
    const el = document.getElementById('issuesCard');
    if (!issues || !issues.length) {
      el.innerHTML = '<div class="card-title">当前评审问题</div><div class="empty-state text-success">✅ 无未解决问题</div>';
      return;
    }
    el.innerHTML = `<div class="card-title">当前评审问题 (${issues.length})</div>` +
      issues.map(b => `
        <div class="issue-item ${String(b.actionable_by || b.owner || '').toLowerCase() === 'framework' ? 'framework-issue' : ''}">
          <div><span class="issue-id">${this.esc(b.id || '')}</span></div>
          <div class="issue-detail">${this.esc(b.required_action || b.detail || b.description || '')}</div>
          <div class="issue-meta">
            target: ${this.esc(b.target || '')}
            ${b.category ? ` · category: ${this.esc(b.category)}` : ''}
            ${b.actionable_by || b.owner ? ` · owner: ${this.esc(b.actionable_by || b.owner)}` : ''}
            ${b.advisor_id ? ` · advisor: ${this.esc(b.advisor_id)}` : ''}
            ${b.severity ? ` · severity: ${this.esc(b.severity)}` : ''}
          </div>
        </div>
      `).join('');
  },

  renderCycleTimeline(cycles) {
    const el = document.getElementById('cycleTimeline');
    if (!cycles.length) { el.innerHTML = '<div class="card-title">评审轮次</div><div class="empty-state">暂无轮次数据</div>'; return; }

    const rows = cycles.map(c => {
      const scorePills = Object.entries(c.scores || {}).map(([k, v]) => {
        const num = Number(v || 0);
        const cls = num >= 0.9 ? 'high' : num >= 0.7 ? 'mid' : 'low';
        return `<span class="score-pill ${cls}" title="${this.esc(k)}">${this.esc(k.substring(0, 18))}: ${num.toFixed(2)}</span>`;
      }).join('');
      const scope = c.global_failure_scope ? `<span class="score-pill low" title="global_failure_scope">${this.esc(c.global_failure_scope)}</span>` : '';
      return `
        <div class="cycle-row">
          <div class="cycle-num">Cycle ${c.cycle}</div>
          <div class="cycle-outcome">${this.outcomeBadge(c.outcome)}</div>
          <div class="cycle-scores">${scorePills}${scope}</div>
          <div class="cycle-issues">${c.issue_count ?? 0} issues</div>
        </div>`;
    }).join('');

    el.innerHTML = `<div class="card-title">评审轮次概览</div>${rows}`;
  },

  // ── Cycles tab ────────────────────────────────
  renderCycles(data) {
    const el = document.getElementById('cyclesContainer');
    if (!data.cycles.length) { el.innerHTML = '<div class="empty-state">暂无轮次数据</div>'; return; }

    el.innerHTML = data.cycles.map(c => `
      <div class="accordion-header" data-run="${this.attr(data.name)}" data-cycle="${this.attr(c.cycle)}" onclick="App.toggleAccordion(this); App.loadCycleDetail(this.dataset.run, Number(this.dataset.cycle), this)">
        <span class="arrow">▶</span>
        <span style="font-weight:600">Cycle ${c.cycle}</span>
        ${this.outcomeBadge(c.outcome)}
        <span class="text-muted" style="margin-left:auto;font-size:12px">
          Global: ${c.global_passed ? '✅' : '❌'}${c.global_failure_scope ? `/${this.esc(c.global_failure_scope)}` : ''} · Results: ${c.result_passed}/${c.result_total} · Removed: ${c.historical_removed_result_count || 0} · Issues: ${c.issue_count ?? 0}
        </span>
      </div>
      <div class="accordion-body" id="cycle-body-${c.cycle}">
        <div class="text-muted">加载中...</div>
      </div>
    `).join('');
  },

  async loadCycleDetail(name, cycle, headerEl) {
    const bodyEl = document.getElementById(`cycle-body-${cycle}`);
    if (bodyEl.dataset.loaded) return;
    try {
      const resp = await fetch(this.runApi(name, `/cycles/${cycle}`));
      const data = await resp.json();
      bodyEl.dataset.loaded = '1';
      this.renderCycleContent(bodyEl, data, name);
    } catch (e) { bodyEl.innerHTML = '<div class="text-error">加载失败</div>'; }
  },

  renderCycleContent(el, data, runName) {
    let html = '';

    if (data.metrics && Object.keys(data.metrics).length) {
      const m = data.metrics;
      html += `<div class="cycle-metrics">
        <span>scope: <strong>${this.esc(m.global_failure_scope || 'n/a')}</strong></span>
        <span>failed: ${m.current_failed_result_count ?? m.failed_result_count ?? 0}</span>
        <span>unreviewed: ${m.unreviewed_new_result_count ?? 0}</span>
        <span>removed: ${m.historical_removed_result_count ?? 0}</span>
      </div>`;
    }

    // Global reviews
    if (data.global_reviews.length) {
      html += '<div class="card-title">全局评审</div>';
      html += data.global_reviews.map(r => `
        <div class="review-card ${r.passed ? 'passed' : 'failed'}">
          <div class="review-header">
            <span class="review-advisor">${this.esc(r.advisor_id)}</span>
            <span class="text-muted">${this.esc(r.role_name)}</span>
            ${this.statusBadge(r.passed ? 'passed' : 'failed', 'badge-sm')}
            ${r.schema_valid === false ? '<span class="badge badge-sm" style="background:rgba(224,175,104,.15);color:#e0af68">schema repair ×' + r.repair_attempts + '</span>' : ''}
            ${r.parser_mode ? `<span class="badge badge-sm badge-mode">${this.esc(r.parser_mode)}</span>` : ''}
            ${r.path ? `<span class="action-link" data-run="${this.attr(runName)}" data-path="${this.attr(r.path)}" onclick="event.stopPropagation(); App.openFile(this.dataset.run, this.dataset.path)">查看 JSON</span>` : ''}
          </div>
          <div class="review-feedback">${this.esc(r.feedback || r.feedback_detail || '').substring(0, 500)}</div>
          <div class="review-scores">
            ${Object.entries(r.scores || {}).map(([k,v]) => {
              const num = Number(v || 0);
              const cls = num >= 0.9 ? 'high' : num >= 0.7 ? 'mid' : 'low';
              return `<span class="score-pill ${cls}">${this.esc(k)}: ${num.toFixed(2)}</span>`;
            }).join('')}
          </div>
          ${(r.issues || []).length ? `<div class="mt-8">${r.issues.map(b =>
            `<div class="issue-item"><span class="issue-id">${this.esc(b.id||'')}</span> ${this.esc(b.required_action||b.detail||'')}</div>`
          ).join('')}</div>` : ''}
        </div>
      `).join('');
    }

    // Result reviews
    if (data.result_reviews.length) {
      html += '<div class="card-title mt-8">结果评审</div>';
      html += data.result_reviews.map(r => `
        <div class="review-card ${r.passed ? 'passed' : 'failed'}">
          <div class="review-header">
            <span class="review-advisor mono">${this.esc(r.result_file)}</span>
            ${this.verdictBadge(r.verdict)}
            <span class="text-muted">conf: ${(r.confidence || 0).toFixed(2)}</span>
            ${r.schema_valid === false ? '<span class="badge badge-sm" style="background:rgba(224,175,104,.15);color:#e0af68">repair ×' + r.repair_attempts + '</span>' : ''}
            ${r.parser_mode ? `<span class="badge badge-sm badge-mode">${this.esc(r.parser_mode)}</span>` : ''}
            ${r.path ? `<span class="action-link" data-run="${this.attr(runName)}" data-path="${this.attr(r.path)}" onclick="event.stopPropagation(); App.openFile(this.dataset.run, this.dataset.path)">查看 JSON</span>` : ''}
          </div>
          <div class="review-feedback">${this.esc(r.feedback_detail || r.feedback || '').substring(0, 500)}</div>
        </div>
      `).join('');
    }

    // Summary snapshot link
    if (data.summary_snapshot) {
      html += `<div class="card-title mt-8">Summary 快照</div>`;
      html += `<div class="card" style="max-height:300px;overflow-y:auto;font-size:12px">${this.renderMarkdown(data.summary_snapshot).substring(0, 5000)}</div>`;
    }

    el.innerHTML = html || '<div class="text-muted">无评审数据</div>';
  },

  // ── Results tab ───────────────────────────────
  renderResults(data) {
    const el = document.getElementById('resultsContainer');
    const activeResults = data.results || [];
    const removedResults = data.removed_results || [];
    if (!activeResults.length && !removedResults.length) { el.innerHTML = '<div class="empty-state">暂无漏洞结果</div>'; return; }

    const activeHtml = activeResults.map(r => `
      <div class="result-card" data-run="${this.attr(data.name)}" data-path="${this.attr(r.path || ('results/' + r.filename))}" onclick="App.openFile(this.dataset.run, this.dataset.path)">
        <div class="result-header">
          <span class="result-name">${this.esc(r.filename)}</span>
          ${this.verdictBadge(r.verdict)}
          ${this.lifecycleBadge(r)}
          ${r.multi_finding ? '<span class="badge badge-sm badge-warning">multi-finding</span>' : ''}
          <span class="result-verdict text-muted">conf: ${(r.confidence || 0).toFixed(2)} · cycle ${r.review_cycle}</span>
          <span class="result-title">${this.esc(r.title || '')}</span>
          ${r.related_to ? `<span class="text-muted">related: ${this.esc(r.related_to)}</span>` : ''}
          ${r.review_path ? `<span class="action-link" data-run="${this.attr(data.name)}" data-path="${this.attr(r.review_path)}" onclick="event.stopPropagation(); App.openFile(this.dataset.run, this.dataset.path)">评审 JSON</span>` : ''}
        </div>
        <div class="review-feedback mt-8">${this.esc(r.feedback_detail || r.feedback || '').substring(0, 260)}</div>
      </div>
    `).join('');

    const removedHtml = removedResults.length ? `
      <div class="card-title mt-8">已迁移/撤回结果</div>
      ${removedResults.map(r => `
        <div class="result-card result-card-muted" ${r.path ? `data-run="${this.attr(data.name)}" data-path="${this.attr(r.path)}" onclick="App.openFile(this.dataset.run, this.dataset.path)"` : ''}>
          <div class="result-header">
            <span class="result-name">${this.esc(r.filename)}</span>
            <span class="badge badge-sm badge-failed">${this.esc(r.lifecycle_status || 'inactive')}</span>
            <span class="text-muted">cycle ${r.cycle || '-'}</span>
            ${r.meta_path ? `<span class="action-link" data-run="${this.attr(data.name)}" data-path="${this.attr(r.meta_path)}" onclick="event.stopPropagation(); App.openFile(this.dataset.run, this.dataset.path)">迁移 JSON</span>` : ''}
          </div>
          <div class="review-feedback mt-8">${this.esc(r.reason || '').substring(0, 260)}</div>
        </div>
      `).join('')}
    ` : '';

    el.innerHTML = activeHtml + removedHtml;
  },

  // ── Sessions tab ──────────────────────────────
  async loadSessions() {
    if (!this.currentRun) return;
    const runName = this.currentRun;
    const el = document.getElementById('sessionsContainer');
    el.innerHTML = '<div class="text-muted">加载中...</div>';
    try {
      const resp = await fetch(this.runApi(runName, '/sessions'));
      const sessions = await resp.json();
      if (this.currentRun !== runName) return;
      this.renderSessions(sessions);
    } catch (e) { if (this.currentRun === runName) el.innerHTML = '<div class="text-error">加载失败</div>'; }
  },

  renderSessions(sessions) {
    const el = document.getElementById('sessionsContainer');
    if (!sessions.length) { el.innerHTML = '<div class="empty-state">暂无会话记录</div>'; return; }

    // Separate jsonl sessions from call-based sessions
    const jsonlSessions = sessions.filter(s => s.format === 'jsonl');
    const callSessions = sessions.filter(s => s.format !== 'jsonl');

    let html = '';

    // JSONL session files
    if (jsonlSessions.length) {
      html += '<div class="card-title" style="margin-bottom:8px">会话文件 (JSONL)</div>';
      jsonlSessions.forEach(s => {
        const sessionIdShort = s.session_id.length > 40 ? s.session_id.substring(0, 40) + '…' : s.session_id;
        html += `
          <div class="session-group">
            <div class="session-name" style="display:flex;align-items:center;gap:8px">
              <span>${this.esc(s.worker_id)}</span>
              <span class="text-muted" style="font-size:11px">${this.fmtSize(s.size)}</span>
              <span class="action-link" data-run="${this.attr(this.currentRun)}" data-path="${this.attr(s.jsonl_path)}" onclick="App.openSessionFile(this.dataset.run, this.dataset.path)">查看对话</span>
            </div>
            <div class="text-muted" style="font-size:11px;margin-bottom:6px">${this.esc(sessionIdShort)}</div>
          </div>`;
      });
    }

    // Legacy call-based sessions
    if (callSessions.length) {
      html += '<div class="card-title mt-8" style="margin-bottom:8px">会话记录 (Calls)</div>';
      callSessions.forEach(s => {
        html += `
          <div class="session-group">
            <div class="session-name">${this.esc(s.session_id)}</div>
            ${s.calls.map(c => `
              <div class="call-row">
                <div class="call-turn">#${c.turn}</div>
                <div class="call-agent">${this.esc(c.agent_id)}</div>
                <div class="call-size">↑${this.fmtSize(c.user_prompt_len)} ↓${this.fmtSize(c.output_len)}</div>
                <div class="call-duration">${c.duration_ms ? (c.duration_ms / 1000).toFixed(1) + 's' : '-'}</div>
                <div class="call-status">${this.statusBadge(c.status, 'badge-sm')}</div>
                <div class="file-actions">
                  ${Object.entries({user_prompt:'Prompt', system_prompt:'System', response:'Response', stdout:'Stdout', stderr:'Stderr', request:'Req'}).map(([key,label]) =>
                    c.files && c.files[key] ? `<span class="action-link" data-run="${this.attr(this.currentRun)}" data-path="${this.attr(c.files[key])}" onclick="App.openFile(this.dataset.run, this.dataset.path)">${label}</span>` : ''
                  ).join('')}
                  ${c.files && c.files.stdout_events ? `<span class="action-link" data-run="${this.attr(this.currentRun)}" data-path="${this.attr(c.files.stdout_events)}" onclick="App.openFile(this.dataset.run, this.dataset.path)">Events</span>` : ''}
                </div>
                ${c.error ? `<div class="text-error" style="font-size:11px;flex:1">${this.esc(c.error).substring(0, 60)}</div>` : ''}
              </div>
            `).join('')}
          </div>`;
      });
    }

    el.innerHTML = html || '<div class="empty-state">暂无会话记录</div>';
  },

  // ── Session JSONL viewer (pi-style) ───────────
  async openSessionFile(runName, path) {
    try {
      const resp = await fetch(this.runApi(runName, `/session-file?path=${encodeURIComponent(path)}`));
      const data = await resp.json();
      document.getElementById('fileModalTitle').textContent = data.path || path;
      const mc = document.getElementById('fileModal').querySelector('.modal-content');
      mc.style.maxWidth = '1100px';
      const body = document.getElementById('fileModalBody');
      body.innerHTML = this.renderSessionConversation(data);
      document.getElementById('fileModal').classList.add('open');
    } catch (e) { console.error('openSessionFile failed', e); alert('Failed to load session file'); }
  },

  renderSessionConversation(data) {
    const meta = data.session_meta || {};
    const events = data.events || [];

    let html = '';

    // Header card
    html += '<div class="session-header-card">';
    html += '<h1>Session</h1>';
    html += '<div class="session-header-info">';
    if (meta.id) html += `<div class="info-item"><span class="info-label">Session ID</span><span class="info-value">${this.esc(meta.id)}</span></div>`;
    if (meta.timestamp) html += `<div class="info-item"><span class="info-label">Started</span><span class="info-value">${this.esc(meta.timestamp)}</span></div>`;
    if (meta.cwd) html += `<div class="info-item"><span class="info-label">Working Dir</span><span class="info-value">${this.esc(meta.cwd)}</span></div>`;
    html += '</div></div>';

    // Progress stats
    const msgEvents = events.filter(e => e.type === 'message');
    const userMsgs = msgEvents.filter(e => e.role === 'user');
    const assistantMsgs = msgEvents.filter(e => e.role === 'assistant');
    const toolResultMsgs = msgEvents.filter(e => e.role === 'toolResult');
    const toolCalls = msgEvents.reduce((n, e) => n + (e.parts || []).filter(p => p.type === 'toolCall').length, 0);

    html += '<div class="session-progress-bar">';
    html += `<span class="progress-stat"><span class="progress-num">${userMsgs.length}</span>User</span>`;
    html += `<span class="progress-stat"><span class="progress-num">${assistantMsgs.length}</span>Assistant</span>`;
    html += `<span class="progress-stat"><span class="progress-num">${toolCalls}</span>Tool Calls</span>`;
    html += `<span class="progress-stat"><span class="progress-num">${toolResultMsgs.length}</span>Results</span>`;
    html += '</div>';

    // Merge consecutive toolResult messages into the preceding assistant message
    const mergedEvents = this._mergeToolResults(events);

    // Render events
    for (const event of mergedEvents) {
      if (event.type === 'model_change') {
        html += `<div class="model-change-event">Model: <span class="model-name">${this.esc(event.provider || '')}/${this.esc(event.modelId || '')}</span></div>`;
        continue;
      }
      if (event.type === 'thinking_level_change') {
        const level = (event.thinkingLevel || '').toLowerCase();
        const colorCls = 'thinking-' + ({off:'off',minimal:'minimal',low:'low',medium:'medium',high:'high','x-high':'xhigh'}[level] || 'off');
        html += `<div class="thinking-level-event"><span class="thinking-level-label ${colorCls}">Thinking: ${this.esc(event.thinkingLevel || '')}</span></div>`;
        continue;
      }
      if (event.type === 'message') {
        html += this.renderPiMessage(event);
        continue;
      }
      // Unknown event
      if (event.type !== 'raw') {
        html += `<div class="model-change-event text-muted" style="font-size:10px">[Line ${event.line}] ${this.esc(event.type)}: ${this.esc(event.summary || '').substring(0, 80)}</div>`;
      }
    }

    return html || '<div class="empty-state">Empty session</div>';
  },

  // Merge consecutive toolResult messages as inline results in the preceding assistant message
  _mergeToolResults(events) {
    const result = [];
    for (const event of events) {
      if (event.type === 'message' && event.role === 'toolResult') {
        // Attach to previous assistant message
        if (result.length > 0 && result[result.length - 1].type === 'message' && result[result.length - 1].role === 'assistant') {
          if (!result[result.length - 1]._toolResults) result[result.length - 1]._toolResults = [];
          result[result.length - 1]._toolResults.push(event);
        }
        continue;
      }
      result.push(event);
    }
    return result;
  },

  renderPiMessage(event) {
    const role = event.role;
    const parts = event.parts || [];
    const ts = event.timestamp || '';
    const timeStr = ts ? ts.split('T')[1]?.replace(/\.\d+Z$/, '').replace('Z', '') : '';

    if (role === 'user') {
      const texts = parts.filter(p => p.type === 'text').map(p => p.text).join('\n');
      return `<div class="user-message">
        ${timeStr ? `<div class="message-timestamp">${timeStr}</div>` : ''}
        <div class="message-text">${this.renderMarkdown(texts)}</div>
      </div>`;
    }

    if (role === 'assistant') {
      let html = `<div class="assistant-message">`;
      if (timeStr) html += `<div class="message-timestamp">${timeStr}</div>`;

      // Render parts in order
      for (const part of parts) {
        if (part.type === 'thinking') {
          html += this.renderThinkingBlock(part);
        } else if (part.type === 'text') {
          html += `<div class="assistant-text-content">${this.renderMarkdown(part.text)}</div>`;
        } else if (part.type === 'toolCall') {
          html += this.renderToolCall(part);
        }
      }

      // Inline tool results (merged)
      const toolResults = event._toolResults || [];
      for (const tr of toolResults) {
        html += this.renderToolResultInline(tr);
      }

      html += '</div>';
      return html;
    }

    // Standalone toolResult (if no preceding assistant message)
    if (role === 'toolResult') {
      return this.renderToolResultInline(event);
    }

    // Fallback
    return `<div class="model-change-event text-muted">[${role}]</div>`;
  },

  renderThinkingBlock(part) {
    const text = part.text || '';
    const preview = text.length > 120 ? text.substring(0, 120) + '...' : text;
    const uid = 'think_' + Math.random().toString(36).substr(2, 6);
    return `<div class="thinking-block">
    <button class="thinking-toggle-btn" onclick="
      var c=document.getElementById('${uid}');
      if(c.style.display==='none'){c.style.display='block';this.textContent='▼ hide'}else{c.style.display='none';this.textContent='▶ thinking'}
    ">▶ thinking</button>
    <div id="${uid}" class="thinking-text" style="display:none">${this.esc(text)}</div>
  </div>`;
  },

  renderToolCall(part) {
    const name = part.name || 'unknown';
    const args = part.arguments || {};

    // Determine tool type for styling
    let statusCls = 'pending'; // default
    let headerHtml = '';

    if (name === 'bash' || name === 'shell' || name === 'exec') {
      const cmd = args.command || args.cmd || '';
      headerHtml = `<span class="tool-name">${this.esc(name)}</span> <span class="tool-command">${this.esc(cmd.substring(0, 200))}</span>`;
    } else if (name === 'read' || name === 'cat' || name === 'head') {
      const path = args.path || args.file || '';
      headerHtml = `<span class="tool-name">${this.esc(name)}</span> <span class="tool-path">${this.esc(path)}</span>`;
    } else if (name === 'write' || name === 'edit') {
      const path = args.path || args.file || '';
      headerHtml = `<span class="tool-name">${this.esc(name)}</span> <span class="tool-path">${this.esc(path)}</span>`;
    } else {
      headerHtml = `<span class="tool-name">${this.esc(name)}</span>`;
    }

    // Build arguments display
    const argsStr = JSON.stringify(args, null, 2);
    const maxArgsLen = 600;
    const truncated = argsStr.length > maxArgsLen;
    const displayArgs = truncated ? argsStr.substring(0, maxArgsLen) + '\n...' : argsStr;
    const argsUid = 'args_' + Math.random().toString(36).substr(2, 6);

    return `<div class="tool-execution ${statusCls}">
    <div class="tool-header">${headerHtml}</div>
    <button class="thinking-toggle-btn" onclick="
      var c=document.getElementById('${argsUid}');
      if(c.style.display==='none'){c.style.display='block';this.textContent='▼ hide args'}else{c.style.display='none';this.textContent='▶ show args'}
    ">▶ show args</button>
    <div id="${argsUid}" class="tool-output" style="display:none"><pre>${this.esc(displayArgs)}</pre></div>
  </div>`;
  },

  renderToolResultInline(event) {
    const parts = event.parts || [];
    const textParts = parts.filter(p => p.type === 'text' || p.type === 'toolResult');
    const text = textParts.map(p => p.text || '').join('\n');
    const isError = event.isError || parts.some(p => p.isError);
    const statusCls = isError ? 'has-error' : '';
    const toolName = event.toolName || '';

    const maxLen = 2000;
    const truncated = text.length > maxLen;
    const preview = truncated ? text.substring(0, maxLen) : text;
    const uid = 'result_' + Math.random().toString(36).substr(2, 6);

    let html = `<div class="tool-result-message ${statusCls}">`;
    html += `<div class="tool-result-header">${toolName ? this.esc(toolName) + ' — ' : ''}Output${truncated ? ` (${text.length} bytes)` : ''}</div>`;
    html += `<div class="tool-result-output" id="${uid}">${this.esc(preview)}${truncated ? '\n\n... truncated' : ''}</div>`;
    if (truncated) {
      html += `<button class="thinking-toggle-btn" onclick="
        var c=document.getElementById('${uid}');
        if(c.dataset.full){if(c.dataset.full==='1'){c.textContent=c.dataset.preview;c.dataset.full='0';this.textContent='\u25B6 show full'}else{c.textContent=c.dataset.fullText;c.dataset.full='1';this.textContent='\u25BC truncate'}}
      ">\u25B6 show full</button>`;
      html += `<script>document.getElementById('${uid}').dataset.preview=document.getElementById('${uid}').textContent;document.getElementById('${uid}').dataset.fullText=${JSON.stringify(JSON.stringify(text))};<\/script>`;
    }
    html += '</div>';
    return html;
  },

  // ── Files tab ─────────────────────────────────
  async loadFiles() {
    if (!this.currentRun) return;
    const runName = this.currentRun;
    const el = document.getElementById('filesContainer');
    el.innerHTML = '<div class="text-muted">加载中...</div>';
    try {
      const resp = await fetch(this.runApi(runName, '/files'));
      const files = await resp.json();
      if (this.currentRun !== runName) return;
      this.currentFiles = files;
      this.renderFiles(this.currentFiles);
    } catch (e) { if (this.currentRun === runName) el.innerHTML = '<div class="text-error">加载失败</div>'; }
  },

  renderFiles(files) {
    const el = document.getElementById('filesContainer');
    if (!files.length) { el.innerHTML = '<div class="empty-state">暂无文件</div>'; return; }

    const groups = {};
    files.forEach(f => {
      if (!groups[f.category]) groups[f.category] = [];
      groups[f.category].push(f);
    });

    const body = Object.entries(groups).map(([category, items]) => `
      <div class="file-group">
        <div class="file-group-title">${this.esc(category)} (${items.length})</div>
        ${items.map(f => `
          <div class="file-row" data-run="${this.attr(this.currentRun)}" data-path="${this.attr(f.path)}" onclick="App.openFile(this.dataset.run, this.dataset.path)" title="${this.attr(f.path)}">
            <div class="file-path">${this.esc(f.path)}</div>
            <div class="file-type">${this.esc(f.type)}</div>
            <div class="file-size">${this.fmtSize(f.size)}</div>
          </div>
        `).join('')}
      </div>
    `).join('');

    el.innerHTML = `
      <div class="file-toolbar">
        <input id="fileSearchInput" placeholder="搜索文件路径 / 分类..." oninput="App.filterFiles(this.value)">
        <span class="text-muted">${files.length} files</span>
      </div>
      ${body}
    `;
  },

  filterFiles(query) {
    const q = String(query || '').toLowerCase();
    const filtered = this.currentFiles.filter(f =>
      f.path.toLowerCase().includes(q) || f.category.toLowerCase().includes(q) || f.type.toLowerCase().includes(q)
    );
    this.renderFiles(filtered);
    const input = document.getElementById('fileSearchInput');
    if (input) { input.value = query; input.focus(); }
  },

  // ── Log tab ───────────────────────────────────
  async loadLog() {
    if (!this.currentRun) return;
    const runName = this.currentRun;
    try {
      const resp = await fetch(this.runApi(runName, '/log?lines=500'));
      const data = await resp.json();
      if (this.currentRun !== runName) return;
      const el = document.getElementById('logContent');
      el.textContent = data.content || '(empty)';
      el.scrollTop = el.scrollHeight;
    } catch (e) { console.error('loadLog failed', e); }
  },

  // ── Tab switching ─────────────────────────────
  switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.toggle('active', t.id === `tab${tab.charAt(0).toUpperCase() + tab.slice(1)}`));
    if (tab === 'sessions') this.loadSessions();
    if (tab === 'files') this.loadFiles();
    if (tab === 'log') this.loadLog();
  },

  // ── File viewer ───────────────────────────────
  async openFile(runName, path) {
    try {
      const resp = await fetch(this.runApi(runName, `/file?path=${encodeURIComponent(path)}`));
      const data = await resp.json();
      document.getElementById('fileModalTitle').textContent = data.path || path;
      const mc = document.getElementById('fileModal').querySelector('.modal-content');
      mc.style.maxWidth = '';
      const body = document.getElementById('fileModalBody');
      if (data.type === 'jsonl') {
        // Open in session viewer — wider modal
        const mc = document.getElementById('fileModal').querySelector('.modal-content');
        mc.style.maxWidth = '1100px';
        body.innerHTML = `<div style="text-align:center;padding:20px">
          <p>这是一个会话记录文件 (.jsonl)</p>
          <button class="btn" style="margin-top:12px" data-run="${this.attr(runName)}" data-path="${this.attr(path)}" onclick="App.openSessionFile(this.dataset.run, this.dataset.path)">查看格式化对话</button>
        </div>`;
      } else if (data.type === 'markdown') {
        body.innerHTML = this.renderMarkdown(data.content);
      } else if (data.type === 'json') {
        try {
          body.innerHTML = `<pre>${this.esc(JSON.stringify(JSON.parse(data.content), null, 2))}</pre>`;
        } catch { body.innerHTML = `<pre>${this.esc(data.content)}</pre>`; }
      } else {
        body.innerHTML = `<pre>${this.esc(data.content)}</pre>`;
      }
      document.getElementById('fileModal').classList.add('open');
    } catch (e) { console.error('openFile failed', e); }
  },

  closeFile() {
    document.getElementById('fileModal').classList.remove('open');
  },

  // ── Accordion ─────────────────────────────────
  toggleAccordion(header) {
    const body = header.nextElementSibling;
    const isOpen = header.classList.toggle('open');
    body.classList.toggle('open', isOpen);
  },

  // ── Duration timer ───────────────────────────
  _durationTimer: null,
  _durationSeconds: 0,

  _startDurationTimer(isRunning) {
    clearInterval(this._durationTimer);
    if (!isRunning || !this.currentRunData) return;
    this._durationSeconds = this._estimateDuration(this.currentRunData);
    this._durationTimer = setInterval(() => {
      this._durationSeconds += 1;
      const el = document.getElementById('runDuration');
      if (el) el.textContent = '⏳ ' + this.fmtDuration(this._durationSeconds);
    }, 1000);
  },

  fmtDuration(seconds) {
    if (!seconds || seconds <= 0) return '-';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  },

  // Compute duration from backend timestamps when possible.
  _estimateDuration(data) {
    if (typeof data.duration_seconds === 'number' && data.duration_seconds > 0) return data.duration_seconds;
    const startStr = data.start_time || '';
    if (!startStr) return 0;
    const m = startStr.match(/(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})/);
    if (!m) return 0;
    const startMs = new Date(m[1]+'-'+m[2]+'-'+m[3]+'T'+m[4]+':'+m[5]+':'+m[6]+'Z').getTime();
    if (isNaN(startMs)) return 0;

    if (data.status === 'running') {
      const nowMs = Date.now();
      const dur = Math.floor((nowMs - startMs) / 1000);
      return dur > 0 ? dur : 0;
    }

    const lastStr = data.last_activity || '';
    if (lastStr) {
      const lastMs = new Date(lastStr).getTime();
      if (!isNaN(lastMs) && lastMs > startMs) {
        return Math.floor((lastMs - startMs) / 1000);
      }
    }

    return 0;
  },

  // ── Delete run ───────────────────────────────
  showDeleteModal() {
    if (!this.currentRun) return;
    document.getElementById('deleteRunName').textContent = this.currentRun;
    document.getElementById('deleteModal').classList.add('open');
  },

  closeDeleteModal() {
    document.getElementById('deleteModal').classList.remove('open');
  },

  async confirmDeleteRun() {
    if (!this.currentRun) return;
    const name = this.currentRun;
    const btn = document.getElementById('confirmDeleteBtn');
    btn.disabled = true;
    btn.textContent = '删除中...';
    try {
      const resp = await fetch(this.runApi(name), { method: 'DELETE' });
      if (!resp.ok) {
        const err = await resp.json();
        alert('删除失败: ' + (err.detail || '未知错误'));
        return;
      }
      // Success – reset view and reload
      this.currentRun = null;
      this.currentRunData = null;
      clearInterval(this._durationTimer);
      document.getElementById('runDetail').style.display = 'none';
      document.getElementById('welcomeView').style.display = 'flex';
      this.closeDeleteModal();
      await this.loadRuns();
    } catch (e) {
      alert('删除失败: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = '删除';
    }
  },

  // ── Helpers ───────────────────────────────────
  esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s || '');
    return d.innerHTML;
  },

  runApi(name, suffix = '') {
    return `/api/runs/${encodeURIComponent(String(name || ''))}${suffix}`;
  },

  attr(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  },

  fmtSize(bytes) {
    if (!bytes) return '0';
    if (bytes < 1024) return bytes + 'B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'K';
    return (bytes / 1024 / 1024).toFixed(1) + 'M';
  },

  statusBadge(status, extra = '') {
    const s = String(status || 'unknown').toLowerCase();
    const label = {
      completed: '完成',
      succeeded: '成功',
      failed: '失败',
      running: '运行中',
      passed: '通过',
      pending: '等待',
      queued: '排队',
      timeout: '超时',
      error: '错误',
      interrupted: '中断',
      cancelled: '取消',
      stopped: '停止',
      review_error: '评审契约错误',
      review_plateau: '评审停滞',
      summary_incomplete: 'Summary 未收敛',
      runtime_output_limit: '输出超限',
      runtime_timeout: '运行超时',
      blocked_context_window: '上下文超限',
      blocked_quota: '额度受限',
      provider_rate_limited: '限流',
      model_contract_violation: '模型契约错误',
      no_workspace: '无工作区',
    }[s] || s;
    return `<span class="badge badge-${s} ${extra}">${label}</span>`;
  },

  outcomeBadge(outcome) {
    const map = {
      all_passed: { cls: 'completed', label: '全部通过' },
      global_failed: { cls: 'failed', label: '全局未通过' },
      results_failed: { cls: 'failed', label: '结果未通过' },
      review_error: { cls: 'failed', label: '评审错误' },
      review_plateau: { cls: 'failed', label: '评审停滞' },
      summary_incomplete: { cls: 'failed', label: 'Summary 未收敛' },
    };
    const m = map[outcome] || { cls: 'unknown', label: outcome || '?' };
    return `<span class="badge badge-${m.cls} badge-sm">${m.label}</span>`;
  },

  verdictBadge(verdict) {
    const v = String(verdict || '').toUpperCase();
    const map = {
      CONFIRMED: { cls: 'completed', label: 'CONFIRMED' },
      PASS: { cls: 'completed', label: 'PASS' },
      FALSE_POSITIVE: { cls: 'failed', label: 'FALSE_POSITIVE' },
      FAIL: { cls: 'failed', label: 'FAIL' },
      INSUFFICIENT_INFO: { cls: 'pending', label: 'INSUFFICIENT' },
    };
    const m = map[v] || { cls: 'unknown', label: v || '-' };
    return `<span class="badge badge-${m.cls} badge-sm">${m.label}</span>`;
  },

  lifecycleBadge(result) {
    const status = String(result.lifecycle_status || result.role || '').toLowerCase();
    if (!status) return '';
    const cls = result.taskable === false || result.active === false ? 'badge-warning' : 'badge-mode';
    const label = result.role && result.lifecycle_status
      ? `${result.role}/${result.lifecycle_status}`
      : status;
    return `<span class="badge badge-sm ${cls}">${this.esc(label)}</span>`;
  },

  renderMarkdown(md) {
    if (!md) return '';
    let html = this.esc(md);
    // Code blocks
    html = html.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
    // Headers
    html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
    html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
    html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
    // Bold
    html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    // Tables
    html = html.replace(/^\|(.+)\|$/gm, (match) => {
      const cells = match.split('|').filter(c => c.trim());
      if (cells.every(c => /^[\s-:]+$/.test(c))) return '';
      const tag = 'td';
      return '<tr>' + cells.map(c => `<${tag}>${c.trim()}</${tag}>`).join('') + '</tr>';
    });
    html = html.replace(/(<tr>[\s\S]*?<\/tr>)/g, '<table>$1</table>');
    html = html.replace(/<\/table>\s*<table>/g, '');
    // List items
    html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
    html = html.replace(/(<li>[\s\S]*?<\/li>)/g, '<ul>$1</ul>');
    html = html.replace(/<\/ul>\s*<ul>/g, '');
    // Line breaks
    html = html.replace(/\n\n/g, '<br><br>');
    html = html.replace(/\n/g, '<br>');
    return '<div class="markdown-content">' + html + '</div>';
  },
};

// Boot
document.addEventListener('DOMContentLoaded', () => App.init());
