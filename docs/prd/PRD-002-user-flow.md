# PRD-002: 用户流程与交互设计

## 核心流程

```
[首页] → [输入 GitHub URL] → [扫描中] → [报告页] → [分享/下载]
```

## 详细流程

### 1. 首页

**布局**：

```
┌─────────────────────────────────────────┐
│  🛡️ SkillGuard                          │
│  AI Agent Skill Security Scanner        │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │ https://github.com/user/skill-name │ │
│  └────────────────────────────────────┘ │
│           [Scan Now]                     │
│                                          │
│  ✓ 10 Security Dimensions               │
│  ✓ 109 Rules (67 Built-in + 42 Custom)  │
│  ✓ Dependency Audit                     │
│  ✓ Sandbox Execution                    │
│                                          │
│  Recent Scans:                           │
│  • skill-a (A - Safe)                   │
│  • skill-b (C - Warning)                │
└─────────────────────────────────────────┘
```

**交互**：
- 输入框支持粘贴 GitHub URL（自动识别格式）
- 支持的格式：
  - `https://github.com/user/repo`
  - `https://github.com/user/repo/tree/main/skills/skill-name`
  - `git@github.com:user/repo.git`
- 点击 "Scan Now" 后跳转到扫描页

### 2. 扫描中页面

**布局**：

```
┌─────────────────────────────────────────┐
│  Scanning: github.com/user/skill-name   │
│                                          │
│  [████████░░░░░░░░░░] 40%               │
│                                          │
│  ✓ Cloning repository                   │
│  ✓ Validating structure                 │
│  ⏳ Running static analysis...          │
│  ⏸ Dependency audit (pending)           │
│  ⏸ Sandbox execution (pending)          │
│                                          │
│  Estimated time: 2 min 30 sec           │
└─────────────────────────────────────────┘
```

**实时更新**：
- WebSocket 推送进度
- 每个阶段完成后显示 ✓
- 预估剩余时间动态更新

### 3. 报告页

**布局**（参考现有 HTML 报告）：

```
┌─────────────────────────────────────────┐
│  [← Back] [Share] [Download PDF] [CN/EN]│
│                                          │
│  skill-name                              │
│  Risk Level: C (Warning)                 │
│  Score: 45/100                           │
│                                          │
│  [Dashboard Stats]                       │
│  • 2 CRITICAL  • 5 HIGH  • 3 MEDIUM     │
│                                          │
│  [Token & Cost Overview]                 │
│  • L1+L2: 12.3K tokens                  │
│  • Typical session: $0.08 (Sonnet)     │
│                                          │
│  [Findings by Dimension]                 │
│  ▼ Prompt Injection (2 findings)        │
│    • CRITICAL: ignore previous...       │
│    • HIGH: role override detected       │
│                                          │
│  ▼ Permission Escalation (1 finding)    │
│    • HIGH: sudo usage detected          │
│                                          │
│  [Dependency Audit]                      │
│  • 3 vulnerabilities found              │
│    - requests 2.28.0 (CVE-2023-xxxxx)   │
│                                          │
│  [Sandbox Execution Results]             │
│  • Network: 2 external requests         │
│    - api.openai.com (expected)          │
│    - analytics.example.com (suspicious) │
│  • Files: 1 write operation             │
│    - /tmp/cache.json                    │
│                                          │
│  [Recommendations]                       │
│  1. Remove sudo from SKILL.md           │
│  2. Update requests to 2.31.0+          │
│  3. Review analytics endpoint           │
└─────────────────────────────────────────┘
```

**交互**：
- 点击 finding 展开详情（文件路径、行号、修复建议）
- 点击 "Share" 生成短链接（7 天有效）
- 点击 "Download PDF" 导出报告
- CN/EN 切换（localStorage 持久化）

### 4. 分享页

**URL 格式**：`https://skillguard.dev/report/{scan_id}`

**功能**：
- 只读报告（无编辑/重新扫描按钮）
- 显示扫描时间、Skill 版本（commit hash）
- 底部显示 "Powered by SkillGuard"

## 边界情况

| 场景 | 处理 |
|------|------|
| 无效 GitHub URL | 输入框下方显示错误提示 |
| 私有仓库 | 提示"需要 GitHub Token"（Phase 2 支持） |
| 非 Skill 仓库 | 扫描后显示"未检测到 SKILL.md" |
| 扫描超时（>10min） | 显示"扫描超时，请稍后重试" |
| 重复扫描 | 检测到 24h 内已扫描，直接返回缓存结果 |

## 响应式设计

- 桌面端：1200px 宽度，左右留白
- 移动端：全宽，卡片堆叠，手风琴折叠
- 暗色模式：跟随系统设置（localStorage 可覆盖）
