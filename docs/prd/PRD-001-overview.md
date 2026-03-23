# PRD-001: SkillGuard 产品概述

## 一句话定位

**AI Agent Skill 安全审计平台** — 输入 GitHub URL，全流程扫描，输出可视化安全报告。

## 背景

AI Agent 生态（Claude Code、Cursor、GitHub Copilot 等）正快速增长，第三方 Skill/Plugin 数量激增。但目前：

- **Claude Code 官方没有 Skill 审计机制**（Anthropic 明确声明不验证插件安全性）
- 用户安装第三方 Skill 时只能"信任作者"，无法评估风险
- 企业批量部署 Skill 缺乏合规审查手段
- Skill 开发者缺少安全自检工具

SkillGuard 填补这一空白。

## 目标用户

| 用户角色 | 核心场景 | 优先级 |
|----------|---------|--------|
| 个人开发者 | 安装前扫一下，看看有没有风险 | P0 (MVP) |
| Skill 开发者 | 发布前自检，拿安全评分/徽章 | P1 |
| 企业安全团队 | 批量审计公司内部署的 Skill | P2 |
| Marketplace 运营方 | 上架前自动化审核 | P3 |

## 产品形态

**Web 服务**（类似 VirusTotal 的体验）：

```
用户打开网站 → 粘贴 GitHub URL → 点击扫描 → 等待结果 → 查看报告
```

## 核心价值

1. **零门槛**：粘贴 URL 即用，无需安装任何工具
2. **全流程**：静态分析 + 依赖审计 + 沙箱运行 + 行为捕获
3. **可视化**：结构化报告 + 风险评分 + 修复建议
4. **可信赖**：基于公开标准（OWASP LLM Top 10、SLSA、Google SAIF）

## 竞品分析

| 竞品 | 做什么 | SkillGuard 差异 |
|------|--------|----------------|
| Snyk | 开源依赖漏洞扫描 | 不懂 Skill 语义、Prompt 注入、Token 成本 |
| Socket.dev | npm 包行为分析 | 仅 npm 生态，不覆盖 Skill 结构 |
| MCP-Scan | MCP Server 安全扫描 | 仅协议层，不覆盖 Prompt/成本/许可证 |
| VirusTotal | 文件/URL 安全扫描 | 不懂 AI Agent 语境 |

**SkillGuard 独特性**：市面上唯一针对 AI Agent Skill 的全维度安全审计产品。

## 商业模式路径

```
Phase A (免费工具引流)    → 积累用户、数据、品牌
Phase B (认证徽章变现)    → Skill 开发者付费拿"SkillGuard Certified"徽章
Phase C (企业版/API)      → 私有化部署、批量审计 API、合规报告导出
```

## 关键指标 (MVP)

| 指标 | 目标 |
|------|------|
| 首次扫描耗时 | < 60s（静态）/ < 5min（全流程） |
| 支持 Skill 格式 | Claude Code SKILL.md, Agent Skills 标准 |
| 审计维度 | 10 维度、109 规则（67 内置 + 42 可配置） |
| 报告语言 | 中/英双语切换 |
