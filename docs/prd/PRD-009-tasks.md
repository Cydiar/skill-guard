# PRD-009: Task Todo

## 总览

| 状态 | 含义 | 标记 |
|------|------|------|
| ✅ 已完成 | 功能已上线或代码已合并 | `[x]` |
| 🔵 进行中 | 正在开发 | `[-]` |
| ⬚ 未开始 | 待启动 | `[ ]` |

---

## Phase 1 — 静态审计引擎

### 后端 + 引擎

- [x] 初始化 FastAPI 项目结构（`app/main.py`, `routers/`, `models.py`）
- [x] 审计引擎集成（`scripts/audit_skill.py :: SkillAuditor`）
- [x] Git 浅克隆 worker（`app/workers/clone.py`）
- [x] 静态审计 worker（`app/workers/audit_task.py`）
- [x] Celery + Redis 任务链（clone → audit → 生成报告）
- [x] API: `POST /api/scan` + `GET /api/scan/{id}/status` + `GET /api/report/{id}`
- [x] WebSocket 实时进度推送
- [x] SQLite 数据库（扫描记录 + Findings 存储）

### 规则架构

- [x] 109 条审计规则拆分：67 内置 + 42 可配置
- [x] `scripts/rules.yaml` 可配置规则文件
- [x] `_load_configurable_rules()` YAML 加载器
- [x] `_apply_configurable_rules()` 通用规则执行器
- [x] 6 个 `_check_*` 函数拆分为内置 + 可配置
- [x] PyYAML 可选依赖（缺失时降级为仅内置规则）

### Rules Editor UI

- [x] `GET /api/rules` + `PUT /api/rules` API
- [x] Pydantic 验证（正则合法性 + severity 枚举）
- [x] `rules.html` 可视化编辑器（Alpine.js）
- [x] 开关、严重度、Pattern、白名单 CRUD
- [x] Save 按钮仅在修改后显示

### 前端页面

- [x] 首页（URL 输入 + 最近扫描列表）
- [x] 扫描进度页（WebSocket 实时更新）
- [x] 报告页（风险评分 + 维度 Findings + Token 估算 + 成本估算）
- [x] 多 Skill 汇总页（Summary）
- [x] 方法论页（Methodology，从 `audit_skill.py` 动态生成）
- [x] 全局 CN/EN 双语切换
- [x] 暗色/亮色主题切换
- [x] Docker Compose 编排（API + Worker + Redis）

### 文档

- [x] PRD-001 ~ PRD-008 产品需求文档
- [x] PRD 展示站点（`docs/prd/index.html`，自动从 Markdown 生成）
- [x] Git 版本管理初始化

---

## Phase 1.5 — Deep Scan（Layer 2 LLM 驱动）

### 已完成

- [x] Deep Scan 数据模型（`deep_scans` 表 + `trace_steps` 表）
- [x] Deep Scan API（`POST /api/deep-scan` + `GET /api/deep-scan/{id}/status`）
- [x] Deep Scan 进度页（`deep_scanning.html`）
- [x] Trace 报告页（`trace_report.html`，截图 + 时间线 + 证据卡片）
- [x] LLM Client 抽象层（`app/engine/llm_client.py`）
- [x] Skill Driver 驱动引擎（`app/engine/skill_driver.py`）
- [x] Evidence Renderer（`app/engine/evidence_renderer.py`）
- [x] Summary 页集成 Deep Scan 状态

### 未完成

- [ ] 截图自动生成（网络请求/文件操作/终端输出渲染为 PNG）
- [ ] AI 自动标注截图（调用 LLM 对截图做风险说明）
- [ ] 多模型支持（目前仅 Claude，待接入 Gemini / GPT）
- [ ] API Key 加密传输 + 用完即销毁
- [ ] 费用预估弹窗（Deep Scan 前展示预计 Token 和费用）

---

## Phase 2 — 依赖审计

- [ ] Python 依赖解析（`requirements.txt` / `pyproject.toml`）
- [ ] Node.js 依赖解析（`package.json` / `package-lock.json`）
- [ ] 集成 OSV API（查询已知 CVE）
- [ ] 版本锁定检查（未固定版本、latest 标签）
- [ ] 许可证解析（从 PyPI/npm 获取依赖许可证）
- [ ] Go 依赖解析（`go.mod`）
- [ ] 报告页增加 Dependencies Tab
- [ ] 集成到任务链（clone → static → deps → 报告）

---

## Phase 3 — 沙箱运行（Layer 1 Stub）

- [ ] 沙箱 Dockerfile 设计（`sandbox/Dockerfile.sandbox`）
- [ ] Claude Stub 实现（模拟工具调用链路）
- [ ] 网络代理（mitmproxy 透明拦截）
- [ ] 文件系统监控（inotifywait）
- [ ] 进程监控（seccomp + audit log）
- [ ] 行为判定引擎（expected / suspicious / dangerous / critical）
- [ ] 行为评分计算 + 与静态评分合并
- [ ] 报告页增加 Behavior Tab
- [ ] 安全加固（rootless Docker, seccomp, 资源限制）

---

## Phase 3+ — 深度验证反驳机制

- [ ] `deep_verdict` 字段扩展（confirmed / mitigated / downgraded / inconclusive / escalated）
- [ ] mitigated 时移除扣分 + 评分重算逻辑
- [ ] 报告页展示验证标签（✅ / 🔴 / ⬇️ / ⚪ / ⬆️）
- [ ] Summary 验证摘要统计（"节省 X 分"）
- [ ] LLM 自动判定逻辑（对比静态 Finding vs 运行时行为）

---

## Phase 4 — 报告系统与认证徽章

- [ ] 报告持久化 + 可分享短链接（7 天有效）
- [ ] SVG 认证徽章生成（`GET /badge/{scan_id}`，多样式）
- [ ] PDF 导出（服务端 HTML → PDF）
- [ ] 历史对比（同一 Skill 多次扫描趋势图）
- [ ] Rate Limiting + GitHub OAuth 登录
- [ ] Landing Page（产品首页 + 定价页）
- [ ] Stripe 集成（Pro 版 $9.9/月）

---

## 后续迭代（Post-MVP）

- [ ] 支持 Cursor Skills、GitHub Copilot Extensions
- [ ] GitHub Action（push 时自动扫描）
- [ ] 用户自定义规则（Web UI 创建 + 导入/导出）
- [ ] API 开放（第三方平台集成）
- [ ] 企业版（私有化部署 + RBAC + 合规报告）
- [ ] 社区 Skill 安全排行榜
- [ ] 一键生成 PR 自动修复检测到的问题
