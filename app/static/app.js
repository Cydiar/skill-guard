/**
 * SkillGuard — Alpine.js components & WebSocket client
 */

/* ── Scan Form (index page) ─────────────────────────────────────── */

function scanForm() {
  return {
    url: '',
    loading: false,
    error: '',

    async submit() {
      this.error = '';
      this.loading = true;

      try {
        const res = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ github_url: this.url }),
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        window.location.href = `/scan/${data.scan_id}`;
      } catch (err) {
        this.error = err.message || 'Failed to start scan';
        this.loading = false;
      }
    },
  };
}


/* ── Scan Progress (scanning page) ──────────────────────────────── */

function scanProgress(scanId, initialStatus, initialMultiSkill) {
  return {
    scanId,
    phase: initialStatus || 'pending',
    progress: 0,
    errorMsg: '',
    isMultiSkill: !!initialMultiSkill,
    totalSkills: 0,
    doneSkills: 0,
    steps: [
      { id: 'pending',  label: 'Queued',    status: 'pending' },
      { id: 'cloning',  label: 'Cloning repository...', status: 'pending' },
      { id: 'scanning', label: 'Running security audit...', status: 'pending' },
      { id: 'done',     label: 'Report ready', status: 'pending' },
    ],

    get phaseLabel() {
      if (this.isMultiSkill && this.totalSkills > 0 && this.phase === 'scanning') {
        return `Scanning skill ${this.doneSkills}/${this.totalSkills}...`;
      }
      const labels = {
        pending: 'Waiting in queue...',
        cloning: 'Cloning repository...',
        cloned: 'Clone complete',
        scanning: 'Running security audit...',
        saving: 'Saving results...',
        done: 'Complete!',
        error: 'Error',
      };
      return labels[this.phase] || this.phase;
    },

    init() {
      this.updateSteps();

      // If already done, redirect
      if (initialStatus === 'done') {
        this.phase = 'done';
        this.progress = 100;
        this.updateSteps();
        setTimeout(() => {
          window.location.href = `/report/${this.scanId}`;
        }, 500);
        return;
      }

      // Try WebSocket first
      this.connectWs();
      // Fallback polling
      this.startPolling();
    },

    connectWs() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${location.host}/api/scan/${this.scanId}/ws`;

      try {
        const ws = new WebSocket(url);

        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          this.handleUpdate(data);
        };

        ws.onerror = () => {
          // WebSocket failed, rely on polling
        };

        ws.onclose = () => {
          // Closed — polling will handle the rest
        };
      } catch (e) {
        // WebSocket not available
      }
    },

    startPolling() {
      const poll = async () => {
        if (this.phase === 'done' || this.phase === 'error') return;

        try {
          const res = await fetch(`/api/scan/${this.scanId}/status`);
          if (res.ok) {
            const data = await res.json();
            this.handleUpdate(data);
          }
        } catch (e) {
          // Network error, keep polling
        }

        if (this.phase !== 'done' && this.phase !== 'error') {
          setTimeout(poll, 2000);
        }
      };

      setTimeout(poll, 1000);
    },

    handleUpdate(data) {
      if (data.phase) this.phase = data.phase;
      if (data.progress !== undefined) this.progress = data.progress;
      if (data.status) this.phase = data.status;
      if (data.error_message) this.errorMsg = data.error_message;
      if (data.error) this.errorMsg = data.error;

      // Multi-skill fields
      if (data.is_multi_skill) this.isMultiSkill = true;
      if (data.total_skills !== undefined) this.totalSkills = data.total_skills;
      if (data.done_skills !== undefined) this.doneSkills = data.done_skills;

      // Update step label for multi-skill
      if (this.isMultiSkill && this.totalSkills > 0) {
        this.steps[2].label = `Scanning skills (${this.doneSkills}/${this.totalSkills})...`;
        if (this.phase === 'done') {
          this.steps[2].label = `Scanned ${this.totalSkills} skills`;
        }
      }

      this.updateSteps();

      if (this.phase === 'done') {
        this.progress = 100;
        setTimeout(() => {
          window.location.href = `/report/${this.scanId}`;
        }, 1000);
      }
    },

    updateSteps() {
      const phaseOrder = ['pending', 'cloning', 'scanning', 'done'];
      const phaseMap = {
        pending: 0,
        cloning: 1,
        cloned: 1,
        scanning: 2,
        saving: 2,
        done: 3,
        error: -1,
      };

      const current = phaseMap[this.phase] ?? 0;

      this.steps.forEach((step, i) => {
        if (this.phase === 'error') {
          if (i <= Math.max(current, 0)) {
            step.status = i === Math.max(current, 0) ? 'error' : 'done';
          } else {
            step.status = 'pending';
          }
        } else if (i < current) {
          step.status = 'done';
        } else if (i === current) {
          step.status = this.phase === 'done' ? 'done' : 'active';
        } else {
          step.status = 'pending';
        }
      });
    },
  };
}


/* ── Report Page ────────────────────────────────────────────────── */

function reportPage(scanId) {
  return {
    scanId: scanId || '',
    lang: localStorage.getItem('sg-lang') || 'en',

    // Deep Scan modal state
    showDeepScanModal: false,
    deepScanModel: 'claude-sonnet-4-6',
    deepScanLoading: false,
    deepScanError: '',

    get deepScanCostEstimate() {
      const pricing = {
        'claude-sonnet-4-6': '$0.05 - $0.20',
        'claude-opus-4-6': '$0.25 - $1.00',
      };
      return pricing[this.deepScanModel] || '$0.05 - $0.20';
    },

    init() {
      this.$watch('lang', (val) => {
        localStorage.setItem('sg-lang', val);
      });
      // Sync lang when navbar toggle changes localStorage
      window.addEventListener('storage', (e) => {
        if (e.key === 'sg-lang' && e.newValue) this.lang = e.newValue;
      });
      // Also poll for same-tab changes (storage event only fires cross-tab)
      setInterval(() => {
        const stored = localStorage.getItem('sg-lang') || 'en';
        if (stored !== this.lang) this.lang = stored;
      }, 500);
    },

    /** Extract the language-appropriate part from bilingual text like "中文名 (English Name)" */
    dimName(raw) {
      const m = raw.match(/^(.+?)\s*\(([^)]+)\)\s*$/);
      if (!m) return raw;
      return this.lang === 'en' ? m[2] : m[1];
    },

    async startDeepScan() {
      this.deepScanError = '';
      this.deepScanLoading = true;

      try {
        const res = await fetch('/api/deep-scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scan_id: this.scanId,
            model: this.deepScanModel,
          }),
        });

        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        if (data.count > 1) {
          // Multi-skill: redirect to first deep scan progress page
          // (user can navigate back to summary to see all)
          window.location.href = `/deep-scan/${data.deep_scan_id}`;
        } else {
          window.location.href = `/deep-scan/${data.deep_scan_id}`;
        }
      } catch (err) {
        this.deepScanError = err.message || 'Failed to start deep scan';
        this.deepScanLoading = false;
      }
    },
  };
}


/* ── Deep Scan Progress ────────────────────────────────────────── */

function deepScanProgress(deepScanId, initialStatus) {
  return {
    deepScanId,
    scanId: '',
    phase: initialStatus || 'pending',
    progress: 0,
    errorMsg: '',
    steps: [
      { id: 'preparing',  label: 'Environment setup',       status: 'pending', detail: '' },
      { id: 'running',    label: 'LLM-driven execution',    status: 'pending', detail: '' },
      { id: 'annotating', label: 'Evidence annotation',     status: 'pending', detail: '' },
      { id: 'generating', label: 'Report generation',       status: 'pending', detail: '' },
    ],

    get phaseLabel() {
      const labels = {
        pending: 'Waiting in queue...',
        preparing: 'Setting up environment...',
        running: 'LLM executing skill...',
        annotating: 'Annotating evidence...',
        generating: 'Generating report...',
        done: 'Complete!',
        error: 'Error',
      };
      return labels[this.phase] || this.phase;
    },

    init() {
      this.updateSteps();

      if (initialStatus === 'done') {
        this.phase = 'done';
        this.progress = 100;
        this.updateSteps();
        setTimeout(() => {
          window.location.href = `/deep-scan/${this.deepScanId}/report`;
        }, 500);
        return;
      }

      this.connectWs();
      this.startPolling();
    },

    connectWs() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${proto}//${location.host}/api/deep-scan/${this.deepScanId}/ws`;

      try {
        const ws = new WebSocket(url);
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          this.handleUpdate(data);
        };
        ws.onerror = () => {};
        ws.onclose = () => {};
      } catch (e) {}
    },

    startPolling() {
      const poll = async () => {
        if (this.phase === 'done' || this.phase === 'error') return;
        try {
          const res = await fetch(`/api/deep-scan/${this.deepScanId}/status`);
          if (res.ok) {
            const data = await res.json();
            this.handleUpdate(data);
          }
        } catch (e) {}
        if (this.phase !== 'done' && this.phase !== 'error') {
          setTimeout(poll, 2000);
        }
      };
      setTimeout(poll, 1000);
    },

    handleUpdate(data) {
      if (data.phase) this.phase = data.phase;
      if (data.status && data.status !== this.phase) this.phase = data.status;
      // Progress only goes forward, never backward
      if (data.progress !== undefined && data.progress > this.progress) {
        this.progress = data.progress;
      }
      if (data.error_message) this.errorMsg = data.error_message;
      if (data.error) this.errorMsg = data.error;

      this.updateSteps();

      if (this.phase === 'done') {
        this.progress = 100;
        setTimeout(() => {
          window.location.href = `/deep-scan/${this.deepScanId}/report`;
        }, 1000);
      }
    },

    updateSteps() {
      const phaseOrder = ['preparing', 'running', 'annotating', 'generating', 'done'];
      const phaseMap = {
        pending: -1,
        preparing: 0,
        running: 1,
        annotating: 2,
        generating: 3,
        done: 4,
        error: -1,
      };

      const current = phaseMap[this.phase] ?? -1;

      this.steps.forEach((step, i) => {
        if (this.phase === 'error') {
          if (i <= Math.max(current, 0)) {
            step.status = i === Math.max(current, 0) ? 'error' : 'done';
          } else {
            step.status = 'pending';
          }
        } else if (i < current) {
          step.status = 'done';
        } else if (i === current) {
          step.status = this.phase === 'done' ? 'done' : 'active';
        } else {
          step.status = 'pending';
        }
      });

      // Mark all as done when phase is 'done'
      if (this.phase === 'done') {
        this.steps.forEach(s => { s.status = 'done'; });
      }
    },
  };
}


/* ── Trace Report ──────────────────────────────────────────────── */

function traceReport() {
  return {
    lang: localStorage.getItem('sg-lang') || 'en',
    traceExpanded: false,

    init() {
      this.$watch('lang', (val) => {
        localStorage.setItem('sg-lang', val);
      });
      setInterval(() => {
        const stored = localStorage.getItem('sg-lang') || 'en';
        if (stored !== this.lang) this.lang = stored;
      }, 500);
    },
  };
}
