# PRD-003: Phase 1 — 静态审计引擎

## 概述

Phase 1 是 SkillGuard 的基座：输入 GitHub URL → 克隆仓库 → 静态分析 → 生成报告。

## 功能范围

### 1.1 仓库获取

**输入**：GitHub URL
**处理**：
- 解析 URL 提取 owner/repo/path
- `git clone --depth 1` 浅克隆（节省时间和空间）
- 如果 URL 指向子目录（如 `repo/tree/main/skills/my-skill`），只分析该子目录
- 克隆到临时目录，扫描完成后清理

**安全约束**：
- 克隆操作在隔离的临时目录中执行
- 最大仓库大小限制：100MB
- 克隆超时：30 秒

### 1.2 结构校验

**检查项**：

| 检查 | 条件 | 严重度 |
|------|------|--------|
| SKILL.md 存在 | 目录包含 SKILL.md 或 skill.md | CRITICAL（缺失则终止） |
| Frontmatter 格式 | YAML frontmatter 可解析 | MEDIUM |
| name 字段 | frontmatter 包含 name | LOW |
| description 字段 | frontmatter 包含 description | LOW |
| allowed-tools 声明 | frontmatter 包含 allowed-tools | MEDIUM（未声明 = 全权限） |

### 1.3 十维度静态扫描

复用现有 `SkillAuditor` 引擎：

| # | 维度 | 参考标准 | 内置 | 可配置 | 合计 |
|---|------|---------|------|--------|------|
| 1 | Prompt 注入检测 | OWASP LLM01 | 10 | 3 (辅助) | 13 |
| 2 | 权限提升分析 | OWASP LLM06 | 10 | — | 10 |
| 3 | 数据外泄风险 | OWASP LLM02 / MCP-Scan TPA | 1 | 18 | 19 |
| 4 | 破坏性操作 | Claude Code Built-in | 17 | — | 17 |
| 5 | 供应链/来源验证 | SLSA / OpenSSF | — | 8 | 8 |
| 6 | 代码安全 (静态分析) | CWE / OWASP | 17 | — | 17 |
| 7 | 凭证与密钥泄露 | OWASP LLM02 | 13 | — | 13 |
| 8 | 权限最小化 | Google SAIF | — | 3 | 3 |
| 9 | 许可证合规 | — | — | 7 | 7 |
| 10 | 资源滥用/无限消耗 | OWASP LLM10 | 1 | 8 | 9 |

**合计**：109 条检测规则（67 内置不可关闭 + 42 可配置 via `rules.yaml`）

### 1.4 Token 消耗估算

复用现有 Token 估算引擎：

- L1 (SKILL.md 直接注入)
- L2 Eager (必须读取的引用文件)
- L2 Lazy (按需读取的引用文件)
- L3 (全部文件)

### 1.5 多轮成本估算

复用 5 条成本规则：

| 规则 | 内容 |
|------|------|
| R1 | 三档场景：Light=3T, Typical=6T, Heavy=15T |
| R2 | 每轮输出 500 tokens |
| R3 | L2 eager 第 2 轮, lazy 第 3 轮加载 |
| R4 | Prompt 缓存：Anthropic 90%, Google 75%, OpenAI 50% 折扣 |
| R5 | 多轮上下文累积 |

### 1.6 修复建议

- 每条 finding 附带具体修复建议（109 条双语映射，含内置与可配置规则）
- 每个维度附带通用修复总结（10 条双语映射）
- 未匹配具体规则时回退到维度级建议

## 输出

### Web 报告

复用现有 HTML 报告模板（Shadcn/ui 设计系统）：
- 风险评分 (0-100) + A-F 等级
- 维度分布仪表板
- Token 消耗可视化
- 多模型成本估算卡片
- 详细 Findings 表格（含修复建议）
- 中/英双语切换
- 暗色/亮色主题

### JSON API 响应

```json
{
  "scan_id": "abc123",
  "skill_name": "example-skill",
  "github_url": "https://github.com/user/repo",
  "commit_sha": "a1b2c3d",
  "scanned_at": "2026-03-20T12:00:00Z",
  "risk_score": 45,
  "risk_level": "C",
  "findings": [...],
  "token_estimate": {...},
  "cost_estimates": [...]
}
```

## 性能目标

| 指标 | 目标 |
|------|------|
| 克隆耗时 | < 10s (100MB 以内) |
| 扫描耗时 | < 5s (单个 Skill) |
| 总响应时间 | < 20s (从提交到报告) |

## 已有代码资产

| 资产 | 路径 | 复用度 |
|------|------|--------|
| 审计引擎 | `scripts/audit_skill.py :: SkillAuditor` | 100% |
| 109 条规则 | 67 内置(`_check_*`) + 42 可配置(`rules.yaml`) | 100% |
| HTML 报告 | `HtmlRenderer.TEMPLATE` | 90%（需适配 Web） |
| 方法论页 | `HtmlRenderer.METHODOLOGY_TEMPLATE` | 100% |
| Token/成本估算 | `estimate_skill_tokens()` + `estimate_costs()` | 100% |
| 双语数据 | `I18N_LABELS` + `DIMENSION_REMEDIATIONS` | 100% |
