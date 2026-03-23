# PRD-007: 技术架构

## 整体架构

```
                    ┌─────────────┐
                    │   Browser   │
                    │  (Next.js)  │
                    └──────┬──────┘
                           │ HTTPS
                    ┌──────▼──────┐
                    │  API Server │
                    │  (FastAPI)  │
                    └──────┬──────┘
                           │
            ┌──────────────┼──────────────┐
            │              │              │
     ┌──────▼──────┐ ┌────▼────┐ ┌───────▼───────┐
     │  Task Queue │ │   DB    │ │  Object Store │
     │  (Celery/   │ │(SQLite→ │ │  (S3/MinIO)   │
     │   Redis)    │ │Postgres)│ │  报告/日志存储  │
     └──────┬──────┘ └─────────┘ └───────────────┘
            │
     ┌──────▼──────┐
     │   Worker    │
     │  ┌────────┐ │
     │  │ Clone  │ │
     │  │ Audit  │ │
     │  │ Deps   │ │
     │  │Sandbox │ │
     │  └────────┘ │
     └─────────────┘
```

## 技术选型

### 前端

| 层 | 选择 | 理由 |
|----|------|------|
| 框架 | Next.js 15 (App Router) | SSR + API Routes 一体化 |
| UI | Tailwind CSS + shadcn/ui | 与现有报告设计系统一致 |
| 语言 | TypeScript | 类型安全 |
| 部署 | Vercel | 零运维，免费额度 |

### 后端

| 层 | 选择 | 理由 |
|----|------|------|
| API | FastAPI (Python) | 审计引擎是 Python，零迁移成本 |
| 任务队列 | Celery + Redis | 异步扫描，WebSocket 推送进度 |
| 数据库 | SQLite → PostgreSQL | MVP 用 SQLite，规模化迁移 PG |
| 对象存储 | 本地 → S3/MinIO | 报告 HTML/JSON 存储 |
| 部署 | Railway / Fly.io | 低成本，支持 Docker |

### 沙箱

| 层 | 选择 | 理由 |
|----|------|------|
| 隔离 | Docker (rootless) | 成熟方案 |
| 网络 | mitmproxy (透明代理) | 捕获 HTTPS 流量 |
| 文件监控 | inotifywait / eBPF | 记录文件系统操作 |
| 进程监控 | seccomp + audit log | 记录进程活动 |

## 数据模型

### 核心表

```sql
-- 扫描记录
CREATE TABLE scans (
    id          TEXT PRIMARY KEY,    -- UUID
    github_url  TEXT NOT NULL,
    commit_sha  TEXT,
    skill_name  TEXT,
    status      TEXT DEFAULT 'pending',  -- pending/cloning/scanning/done/error
    risk_score  INTEGER,
    risk_level  TEXT,                -- A/B/C/D/F
    static_score  INTEGER,
    deps_score    INTEGER,
    behavior_score INTEGER,
    report_path TEXT,                -- S3/local 路径
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP            -- 7 天后过期
);

-- Findings
CREATE TABLE findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT REFERENCES scans(id),
    phase       TEXT,               -- static/deps/behavior
    dimension   TEXT,
    severity    TEXT,
    file_path   TEXT,
    line_number INTEGER,
    description TEXT,
    remediation_zh TEXT,
    remediation_en TEXT
);

-- 依赖漏洞
CREATE TABLE dep_vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT REFERENCES scans(id),
    ecosystem   TEXT,               -- python/node/go
    package     TEXT,
    version     TEXT,
    cve_id      TEXT,
    severity    TEXT,
    fix_version TEXT
);

-- 行为日志
CREATE TABLE behaviors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT REFERENCES scans(id),
    category    TEXT,               -- network/filesystem/process
    detail      JSON,
    verdict     TEXT                -- expected/suspicious/dangerous/critical
);
```

## API 设计

### 提交扫描

```
POST /api/scan
Body: { "github_url": "https://github.com/user/repo" }
Response: { "scan_id": "abc123", "status": "pending" }
```

### 查询进度

```
GET /api/scan/{scan_id}/status
Response: {
    "status": "scanning",
    "phase": "static",
    "progress": 40,
    "phases": {
        "clone": "done",
        "static": "running",
        "deps": "pending",
        "sandbox": "pending"
    }
}
```

### WebSocket 进度推送

```
WS /api/scan/{scan_id}/ws
← { "phase": "static", "progress": 80, "message": "Scanning dimension 8/10" }
← { "phase": "static", "progress": 100, "message": "Static analysis complete" }
← { "phase": "deps", "progress": 0, "message": "Starting dependency audit" }
```

### 获取报告

```
GET /api/report/{scan_id}
Response: { ... full JSON report ... }

GET /api/report/{scan_id}/html
Response: HTML report page

GET /api/badge/{scan_id}
Response: SVG badge
```

## 项目结构

```
skillguard/
├── frontend/                  # Next.js 前端
│   ├── app/
│   │   ├── page.tsx          # 首页（URL 输入）
│   │   ├── scan/[id]/        # 扫描进度页
│   │   └── report/[id]/      # 报告页
│   ├── components/
│   │   ├── ScanForm.tsx
│   │   ├── ProgressBar.tsx
│   │   └── ReportView.tsx
│   └── lib/
│       └── api.ts
├── backend/                   # FastAPI 后端
│   ├── main.py               # API 入口
│   ├── routers/
│   │   ├── scan.py
│   │   └── report.py
│   ├── workers/
│   │   ├── clone.py          # Git 克隆
│   │   ├── static_audit.py   # 静态审计（复用 audit_skill.py）
│   │   ├── dep_audit.py      # 依赖审计
│   │   └── sandbox.py        # 沙箱运行
│   ├── models.py             # 数据模型
│   └── db.py                 # 数据库连接
├── engine/                    # 审计引擎（从现有代码迁移）
│   ├── audit_skill.py        # 核心引擎
│   ├── remediations.py       # 规则库
│   └── cost_model.py         # 成本模型
├── sandbox/                   # 沙箱相关
│   ├── Dockerfile.sandbox    # 沙箱容器镜像
│   ├── claude_stub.py        # Claude 模拟
│   └── behavior_logger.py    # 行为收集
├── docker-compose.yml
└── README.md
```

## 安全考量

| 风险 | 缓解措施 |
|------|---------|
| 恶意仓库攻击服务器 | 沙箱隔离 + 资源限制 + 网络代理 |
| git clone 时执行钩子 | `GIT_CONFIG_NOSYSTEM=1 GIT_TEMPLATE_DIR=` 禁用模板 |
| 大仓库耗尽磁盘 | 100MB 上限 + tmpfs |
| API 滥用 | Rate limit: 10/天 (免费), 100/天 (Pro) |
| 报告链接被猜测 | UUID v4（不可枚举） |
