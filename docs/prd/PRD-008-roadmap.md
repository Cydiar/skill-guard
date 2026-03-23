# PRD-008: 路线图与里程碑

## 全局时间线

```
Phase 1 ──────── Phase 2 ──────── Phase 3 ──────── Phase 4 ────────
静态审计 Web 化    依赖审计          沙箱运行          报告 + 徽章
2 周              1.5 周            2 周              1.5 周
                                                      │
                                                      ▼
                                                  公开发布
```

## Phase 1: 静态审计 Web 化（2 周）

> 目标：跑通 GitHub URL → 克隆 → 静态审计 → Web 报告的完整链路

### Week 1: 后端 + 引擎

| 任务 | 交付物 | 天数 |
|------|--------|------|
| 初始化 FastAPI 项目结构 | `backend/main.py`, `routers/`, `models.py` | 0.5 |
| 迁移审计引擎为独立模块 | `engine/audit_skill.py` → 可 import 调用 | 1 |
| 实现 Git 克隆 worker | `workers/clone.py` (shallow clone + 安全限制) | 0.5 |
| 实现静态审计 worker | `workers/static_audit.py` (调用引擎 → 存数据库) | 1 |
| 实现 Celery 任务链 | clone → audit → 生成报告 | 1 |
| API: POST /scan + GET /status + GET /report | 完整 REST API | 1 |

### Week 2: 前端 + 联调

| 任务 | 交付物 | 天数 |
|------|--------|------|
| 初始化 Next.js 项目 | `frontend/` + shadcn/ui 配置 | 0.5 |
| 首页 (URL 输入 + 提交) | `app/page.tsx` | 0.5 |
| 扫描进度页 (WebSocket) | `app/scan/[id]/page.tsx` | 1 |
| 报告页 (复用现有 HTML 模板逻辑) | `app/report/[id]/page.tsx` | 2 |
| Docker Compose 编排 | `docker-compose.yml` (API + Redis + Worker) | 0.5 |
| 部署到 Railway/Fly.io | 可访问的公网 URL | 0.5 |

### P1 交付标准

- [ ] 用户在浏览器输入 GitHub URL，点击 Scan
- [ ] 20 秒内返回静态审计报告
- [ ] 报告包含：风险评分、10 维度 findings、Token 估算、成本估算、修复建议
- [ ] 支持中英双语切换
- [ ] 支持暗色/亮色主题

---

## Phase 2: 依赖审计（1.5 周）

> 目标：扫描 Python/Node.js 依赖，比对 CVE 数据库

### 任务清单

| 任务 | 交付物 | 天数 |
|------|--------|------|
| Python 依赖解析 | 解析 requirements.txt / pyproject.toml | 0.5 |
| Node.js 依赖解析 | 解析 package.json / package-lock.json | 0.5 |
| 集成 OSV API | 查询已知漏洞 | 1 |
| 版本锁定检查 | 检测未固定版本、latest 标签 | 0.5 |
| 许可证解析 | 从 PyPI/npm 获取依赖许可证信息 | 1 |
| 报告页增加 Dependencies Tab | 前端渲染依赖审计结果 | 1 |
| 集成到任务链 | clone → static → deps → 生成报告 | 0.5 |

### P2 交付标准

- [ ] 自动检测并扫描 Python/Node.js 依赖
- [ ] 标记已知 CVE 并提供修复版本
- [ ] 标记未锁定版本
- [ ] 报告页新增 Dependencies Tab

---

## Phase 3: 沙箱运行（2 周）

> 目标：在 Docker 隔离环境中运行 Skill，捕获网络/文件/进程行为

### Week 1: 沙箱基础设施

| 任务 | 交付物 | 天数 |
|------|--------|------|
| 设计沙箱 Dockerfile | `sandbox/Dockerfile.sandbox` | 0.5 |
| 实现 Claude Stub | `sandbox/claude_stub.py` (模拟工具调用) | 1.5 |
| 网络代理 (mitmproxy) | 拦截并记录所有出站请求 | 1 |
| 文件系统监控 | inotifywait 记录读写操作 | 1 |
| 进程监控 | seccomp profile + audit log | 1 |

### Week 2: 行为分析 + 集成

| 任务 | 交付物 | 天数 |
|------|--------|------|
| 行为判定引擎 | 规则：expected/suspicious/dangerous/critical | 1 |
| 行为评分计算 | 与静态评分合并 | 0.5 |
| 集成到任务链 | clone → static → deps → sandbox → 报告 | 1 |
| 报告页增加 Behavior Tab | 前端渲染行为分析结果 | 1.5 |
| 安全加固 | rootless Docker, seccomp, 资源限制 | 1 |

### P3 交付标准

- [ ] 沙箱在 3 分钟内完成运行
- [ ] 捕获并展示所有网络请求（域名、路径、方法）
- [ ] 捕获并展示文件系统操作（读/写/删除）
- [ ] 行为异常自动标记（suspicious/dangerous/critical）
- [ ] 综合评分 = 静态 × 0.4 + 依赖 × 0.2 + 行为 × 0.4

---

## Phase 4: 报告系统 + 认证徽章（1.5 周）

> 目标：可分享报告链接 + SVG 认证徽章 + 变现基础

### 任务清单

| 任务 | 交付物 | 天数 |
|------|--------|------|
| 报告持久化 + 短链接 | `GET /report/{scan_id}` (7 天有效) | 0.5 |
| SVG 徽章生成 | `GET /badge/{scan_id}` (多种样式) | 1 |
| PDF 导出 | 服务端 HTML → PDF (Playwright/wkhtmltopdf) | 1 |
| 历史对比 | 同一 Skill 多次扫描趋势图 | 1 |
| Rate Limiting + 用户系统 | GitHub OAuth 登录 + 免费/Pro 额度控制 | 1.5 |
| Landing Page | 产品首页 + 定价页 | 1 |
| Stripe 集成 | Pro 版支付 | 1 |

### P4 交付标准

- [ ] 报告可通过短链接分享
- [ ] SVG 徽章可嵌入 GitHub README
- [ ] 支持 PDF 导出
- [ ] GitHub OAuth 登录
- [ ] Pro 版 $9.9/月 付费通道

---

## 后续迭代 (Post-MVP)

| 方向 | 内容 | 优先级 |
|------|------|--------|
| **更多生态** | 支持 Cursor Skills、GitHub Copilot Extensions | P1 |
| **CI/CD 集成** | GitHub Action: push 时自动扫描 | P1 |
| **自定义规则** | 用户/企业可添加自定义检测规则 | P2 |
| **API 开放** | 第三方平台集成 (Marketplace 审核) | P2 |
| **企业版** | 私有化部署 + RBAC + 合规报告 | P3 |
| **社区排行榜** | 按安全评分排名的 Skill 排行榜 | P3 |
| **自动修复** | 一键生成 PR 修复检测到的问题 | P3 |

## 关键风险

| 风险 | 影响 | 缓解 |
|------|------|------|
| Skill 生态增长不如预期 | 用户量不足 | 先做免费工具积累口碑，拓展到其他 Agent 生态 |
| 沙箱被绕过 | 安全事故 | 多层隔离 + rootless + 定期安全审计 |
| Claude Code 官方推出审计功能 | 被替代 | 保持差异化（全流程 + 认证 + 多生态）|
| 恶意仓库 DDoS | 服务不可用 | Rate limit + 队列控制 + 自动扩缩容 |

## 成功标准（发布后 3 个月）

| 指标 | 目标 |
|------|------|
| 总扫描次数 | > 10,000 |
| 月活用户 | > 500 |
| 徽章嵌入 README 数 | > 100 |
| Pro 付费用户 | > 20 |
| GitHub Star (如开源引擎) | > 500 |
