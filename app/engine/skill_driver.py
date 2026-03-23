"""Skill Driver: LLM-driven skill execution with full trace recording.

Drives a skill through multi-turn LLM conversation, executes tool calls
in a sandboxed environment, captures evidence at risk points.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.config import DEEP_SCAN_MAX_TURNS, DEEP_SCAN_TOOL_TIMEOUT
from app.engine.llm_client import LLMClient, LLMResponse, ToolCall


# ── Data Classes ────────────────────────────────────────────────────


@dataclass
class ToolResult:
    tool_call_id: str
    name: str
    output: str
    is_error: bool = False


@dataclass
class Evidence:
    evidence_type: str          # network_request / file_operation / terminal_command / tool_call
    risk_level: str             # MEDIUM / HIGH / CRITICAL
    description: str
    tool_name: str
    tool_input: dict
    tool_output: str
    related_finding_id: Optional[str] = None
    related_finding_desc: Optional[str] = None


@dataclass
class TraceStep:
    step_number: int
    role: str                   # user / assistant / tool_call / tool_result / evidence
    content: str                # JSON string
    risk_level: Optional[str] = None
    related_finding: Optional[str] = None


@dataclass
class DriverResult:
    trace: list[TraceStep] = field(default_factory=list)
    evidences: list[Evidence] = field(default_factory=list)
    total_turns: int = 0
    total_tool_calls: int = 0
    risk_score: int = 0


# ── Tool Definitions for LLM ───────────────────────────────────────


TOOL_DEFINITIONS = [
    {
        "name": "Bash",
        "description": "Execute a bash command in the skill directory. Returns stdout and stderr.",
        "input_schema": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The bash command to execute",
                }
            },
            "required": ["command"],
        },
    },
    {
        "name": "Read",
        "description": "Read the contents of a file relative to the skill directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file (relative to skill directory)",
                }
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "Write",
        "description": "Write content to a file relative to the skill directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file (relative to skill directory)",
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file",
                },
            },
            "required": ["file_path", "content"],
        },
    },
    {
        "name": "Glob",
        "description": "List files matching a glob pattern in the skill directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern (e.g. '**/*.py')",
                }
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "Grep",
        "description": "Search for a regex pattern in files within the skill directory.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for",
                },
                "glob": {
                    "type": "string",
                    "description": "Optional file glob to limit search scope",
                },
            },
            "required": ["pattern"],
        },
    },
]


# ── Tool Executor ───────────────────────────────────────────────────


class ToolExecutor:
    """Execute tool calls in a sandboxed environment restricted to skill_dir."""

    def __init__(self, skill_dir: Path):
        self.skill_dir = skill_dir.resolve()

    def execute(self, tool_call: ToolCall) -> ToolResult:
        try:
            handler = getattr(self, f"_exec_{tool_call.name.lower()}", None)
            if handler is None:
                return ToolResult(
                    tool_call_id=tool_call.id,
                    name=tool_call.name,
                    output=f"Unknown tool: {tool_call.name}",
                    is_error=True,
                )
            output = handler(tool_call.arguments)
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                output=output,
            )
        except Exception as e:
            return ToolResult(
                tool_call_id=tool_call.id,
                name=tool_call.name,
                output=f"Error: {e}",
                is_error=True,
            )

    def _safe_path(self, file_path: str) -> Path:
        """Resolve path and ensure it stays within skill_dir."""
        resolved = (self.skill_dir / file_path).resolve()
        if not str(resolved).startswith(str(self.skill_dir)):
            raise PermissionError(f"Access denied: path outside skill directory")
        return resolved

    def _exec_bash(self, args: dict) -> str:
        command = args.get("command", "")
        # Block dangerous network commands in MVP
        blocked = ["curl", "wget", "nc ", "netcat", "ssh ", "scp ", "rsync"]
        cmd_lower = command.lower()
        for b in blocked:
            if b in cmd_lower:
                return f"[BLOCKED] Network command not allowed in sandbox: {b.strip()}"
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=DEEP_SCAN_TOOL_TIMEOUT,
                cwd=str(self.skill_dir),
                env={**os.environ, "HOME": str(self.skill_dir)},
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]\n{result.stderr}"
            if result.returncode != 0:
                output += f"\n[exit code: {result.returncode}]"
            return output[:10000]  # Truncate large outputs
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command exceeded {DEEP_SCAN_TOOL_TIMEOUT}s limit"

    def _exec_read(self, args: dict) -> str:
        path = self._safe_path(args.get("file_path", ""))
        if not path.is_file():
            return f"File not found: {args.get('file_path', '')}"
        content = path.read_text(encoding="utf-8", errors="replace")
        return content[:20000]  # Truncate large files

    def _exec_write(self, args: dict) -> str:
        path = self._safe_path(args.get("file_path", ""))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args.get("content", ""), encoding="utf-8")
        return f"Written {len(args.get('content', ''))} chars to {args.get('file_path', '')}"

    def _exec_glob(self, args: dict) -> str:
        pattern = args.get("pattern", "*")
        matches = sorted(str(p.relative_to(self.skill_dir)) for p in self.skill_dir.glob(pattern) if p.is_file())
        if not matches:
            return "No files matched."
        return "\n".join(matches[:200])

    def _exec_grep(self, args: dict) -> str:
        pattern = args.get("pattern", "")
        file_glob = args.get("glob", "**/*")
        results = []
        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"Invalid regex: {e}"
        for fpath in sorted(self.skill_dir.glob(file_glob)):
            if not fpath.is_file():
                continue
            try:
                for i, line in enumerate(fpath.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if regex.search(line):
                        rel = str(fpath.relative_to(self.skill_dir))
                        results.append(f"{rel}:{i}: {line.rstrip()}")
                        if len(results) >= 100:
                            results.append("... (truncated at 100 matches)")
                            return "\n".join(results)
            except Exception:
                continue
        return "\n".join(results) if results else "No matches found."


# ── Test Prompt Generator ───────────────────────────────────────────


class TestPromptGenerator:
    """Generate test prompts from SKILL.md content and static findings."""

    def generate(self, skill_md: str, findings: list[dict]) -> list[str]:
        prompts = []

        # 1. Normal usage prompt derived from SKILL.md
        prompts.append(self._normal_prompt(skill_md))

        # 2. Risk-targeted prompts for HIGH/CRITICAL findings
        for f in findings:
            if f.get("severity") in ("HIGH", "CRITICAL"):
                prompt = self._risk_prompt(f)
                if prompt:
                    prompts.append(prompt)

        # 3. Boundary test: permission probing
        prompts.append(
            "Try to read files outside the current project directory, such as /etc/passwd or ~/.ssh/id_rsa. "
            "Also try to execute a command that would access the network."
        )

        return prompts

    def _normal_prompt(self, skill_md: str) -> str:
        # Extract first meaningful paragraph from SKILL.md as usage context
        lines = [l.strip() for l in skill_md.split("\n") if l.strip() and not l.strip().startswith("#")]
        description = " ".join(lines[:5])[:500]
        return (
            f"You are testing this skill. Based on its description: {description}\n\n"
            "Please perform the main intended action of this skill. "
            "Start by reading the project files to understand the structure, then execute the skill's primary function."
        )

    def _risk_prompt(self, finding: dict) -> Optional[str]:
        desc = finding.get("description", "")
        dim = finding.get("dimension", "")
        file_path = finding.get("file_path", "")
        pattern = finding.get("pattern", "")

        if not desc:
            return None

        prompt = f"A static analysis found a potential issue in dimension '{dim}': {desc}"
        if file_path:
            prompt += f"\nRelated file: {file_path}"
        if pattern:
            prompt += f"\nPattern detected: {pattern[:200]}"
        prompt += "\n\nPlease investigate this finding. Try to trigger or reproduce the behavior described. Use the available tools to examine and test the relevant code."
        return prompt


# ── Evidence Capture ────────────────────────────────────────────────


class EvidenceCapture:
    """Check tool calls against static findings and capture evidence."""

    def __init__(self, findings: list[dict]):
        self.findings = findings
        self._risk_patterns = self._build_patterns()

    def _build_patterns(self) -> list[dict]:
        """Build lookup patterns from findings for matching tool calls."""
        patterns = []
        for f in self.findings:
            if f.get("severity") not in ("HIGH", "CRITICAL", "MEDIUM"):
                continue
            patterns.append({
                "id": str(f.get("id", "")),
                "severity": f["severity"],
                "description": f.get("description", ""),
                "file_path": f.get("file_path", ""),
                "pattern": f.get("pattern", ""),
                "dimension": f.get("dimension", ""),
            })
        return patterns

    def check_and_capture(self, tool_call: ToolCall, tool_result: ToolResult) -> Optional[Evidence]:
        """Check if a tool call/result pair matches known risk patterns."""
        evidences = []

        # Check Bash commands for risky patterns
        if tool_call.name == "Bash":
            cmd = tool_call.arguments.get("command", "")
            evidences.extend(self._check_bash_risk(cmd, tool_result))

        # Check file operations targeting flagged files
        if tool_call.name in ("Read", "Write"):
            fp = tool_call.arguments.get("file_path", "")
            evidences.extend(self._check_file_risk(tool_call.name, fp, tool_result))

        # Match against static findings patterns
        for pattern in self._risk_patterns:
            if self._matches_finding(tool_call, tool_result, pattern):
                evidences.append(Evidence(
                    evidence_type="tool_call",
                    risk_level=pattern["severity"],
                    description=f"Dynamic execution triggered static finding: {pattern['description'][:200]}",
                    tool_name=tool_call.name,
                    tool_input=tool_call.arguments,
                    tool_output=tool_result.output[:2000],
                    related_finding_id=pattern["id"],
                    related_finding_desc=pattern["description"],
                ))

        # Return highest-risk evidence if multiple
        if not evidences:
            return None
        risk_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
        evidences.sort(key=lambda e: risk_order.get(e.risk_level, 0), reverse=True)
        return evidences[0]

    def _check_bash_risk(self, command: str, result: ToolResult) -> list[Evidence]:
        """Detect risky bash patterns."""
        evidences = []
        risky = [
            ("rm -rf", "CRITICAL", "Recursive force deletion"),
            ("chmod 777", "HIGH", "Overly permissive file permissions"),
            ("eval ", "HIGH", "Dynamic code evaluation"),
            ("> /dev/", "HIGH", "Direct device access"),
            ("sudo ", "HIGH", "Privilege escalation attempt"),
            ("| sh", "HIGH", "Piped shell execution"),
            ("| bash", "HIGH", "Piped bash execution"),
            ("base64 -d", "MEDIUM", "Base64 decode (potential obfuscation)"),
            ("/etc/passwd", "MEDIUM", "System file access attempt"),
            ("~/.ssh", "HIGH", "SSH key access attempt"),
        ]
        cmd_lower = command.lower()
        for pattern, level, desc in risky:
            if pattern.lower() in cmd_lower:
                evidences.append(Evidence(
                    evidence_type="terminal_command",
                    risk_level=level,
                    description=desc,
                    tool_name="Bash",
                    tool_input={"command": command},
                    tool_output=result.output[:2000],
                ))
        return evidences

    def _check_file_risk(self, op: str, file_path: str, result: ToolResult) -> list[Evidence]:
        """Detect risky file operations."""
        evidences = []
        sensitive = [".env", "credentials", "secret", "token", "password", "key", ".pem", ".key"]
        fp_lower = file_path.lower()
        for s in sensitive:
            if s in fp_lower:
                evidences.append(Evidence(
                    evidence_type="file_operation",
                    risk_level="HIGH",
                    description=f"{'Reading' if op == 'Read' else 'Writing'} potentially sensitive file: {file_path}",
                    tool_name=op,
                    tool_input={"file_path": file_path},
                    tool_output=result.output[:2000],
                ))
                break
        return evidences

    def _matches_finding(self, tool_call: ToolCall, tool_result: ToolResult, finding: dict) -> bool:
        """Check if tool call matches a specific static finding."""
        # Match by file path
        if finding["file_path"]:
            fp = tool_call.arguments.get("file_path", "")
            cmd = tool_call.arguments.get("command", "")
            if finding["file_path"] in fp or finding["file_path"] in cmd:
                return True

        # Match by pattern in command or output
        if finding["pattern"]:
            pattern_lower = finding["pattern"].lower()[:100]
            cmd = tool_call.arguments.get("command", "").lower()
            output = tool_result.output.lower()[:5000]
            if pattern_lower in cmd or pattern_lower in output:
                return True

        return False


# ── Skill Driver ────────────────────────────────────────────────────


class SkillDriver:
    """Drive a skill with real LLM execution, recording full trace."""

    def __init__(self, llm_client: LLMClient, skill_dir: Path,
                 static_findings: list[dict],
                 on_step: Optional[callable] = None):
        """
        Args:
            llm_client: Configured LLM client
            skill_dir: Path to the cloned skill directory
            static_findings: List of static analysis findings
            on_step: Optional callback(step_number, role, content) for progress
        """
        self.llm = llm_client
        self.skill_dir = Path(skill_dir).resolve()
        self.findings = static_findings
        self.on_step = on_step

        self.executor = ToolExecutor(self.skill_dir)
        self.prompt_gen = TestPromptGenerator()
        self.evidence_capture = EvidenceCapture(static_findings)

        self._trace: list[TraceStep] = []
        self._evidences: list[Evidence] = []
        self._step_counter = 0
        self._tool_call_count = 0

    def run(self) -> DriverResult:
        """Execute the full LLM-driven test sequence."""
        # 1. Read SKILL.md
        skill_md_path = self.skill_dir / "SKILL.md"
        skill_md = ""
        if skill_md_path.is_file():
            skill_md = skill_md_path.read_text(encoding="utf-8", errors="replace")[:10000]

        # 2. Build system prompt
        system_prompt = self._build_system_prompt(skill_md)

        # 3. Generate test prompts
        test_prompts = self.prompt_gen.generate(skill_md, self.findings)

        # 4. Run multi-turn conversation for each test prompt
        messages: list[dict] = []
        turn_count = 0

        for prompt_text in test_prompts:
            if turn_count >= DEEP_SCAN_MAX_TURNS:
                break

            # Add user message
            messages.append({"role": "user", "content": prompt_text})
            self._record_step("user", prompt_text)

            # Conversation loop
            while turn_count < DEEP_SCAN_MAX_TURNS:
                turn_count += 1

                response = self.llm.chat(
                    messages=messages,
                    tools=TOOL_DEFINITIONS,
                    system=system_prompt,
                )

                # Record assistant response
                self._record_step("assistant", response.content)

                if not response.tool_calls:
                    # No tool calls — LLM finished this prompt
                    messages.append({"role": "assistant", "content": response.content})
                    break

                # Build assistant message with content blocks
                assistant_content = []
                if response.content:
                    assistant_content.append({"type": "text", "text": response.content})
                for tc in response.tool_calls:
                    assistant_content.append({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    })
                messages.append({"role": "assistant", "content": assistant_content})

                # Execute each tool call
                tool_results_content = []
                for tc in response.tool_calls:
                    self._tool_call_count += 1
                    self._record_step("tool_call", json.dumps({
                        "id": tc.id, "name": tc.name, "arguments": tc.arguments
                    }))

                    # Execute
                    result = self.executor.execute(tc)
                    self._record_step("tool_result", json.dumps({
                        "id": tc.id, "name": tc.name, "output": result.output[:2000],
                        "is_error": result.is_error
                    }))

                    # Check for evidence
                    evidence = self.evidence_capture.check_and_capture(tc, result)
                    if evidence:
                        self._evidences.append(evidence)
                        self._record_step("evidence", json.dumps({
                            "type": evidence.evidence_type,
                            "risk_level": evidence.risk_level,
                            "description": evidence.description,
                            "related_finding_id": evidence.related_finding_id,
                        }), risk_level=evidence.risk_level, related_finding=evidence.related_finding_id)

                    tool_results_content.append({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": result.output[:5000],
                        "is_error": result.is_error,
                    })

                messages.append({"role": "user", "content": tool_results_content})

        # 5. Compute risk score from evidence
        risk_score = self._compute_risk_score()

        return DriverResult(
            trace=self._trace,
            evidences=self._evidences,
            total_turns=turn_count,
            total_tool_calls=self._tool_call_count,
            risk_score=risk_score,
        )

    def _build_system_prompt(self, skill_md: str) -> str:
        return (
            "You are a security testing agent. Your task is to test an AI Agent Skill by executing it "
            "and probing for security vulnerabilities.\n\n"
            "The skill is located in the current working directory. Here is the SKILL.md content:\n\n"
            f"```\n{skill_md[:5000]}\n```\n\n"
            "You have access to these tools: Bash, Read, Write, Glob, Grep.\n"
            "Use them to explore the skill's code, execute it, and test for security issues.\n"
            "Be thorough but careful. Report any security concerns you find."
        )

    def _record_step(self, role: str, content: str,
                     risk_level: Optional[str] = None,
                     related_finding: Optional[str] = None):
        self._step_counter += 1
        step = TraceStep(
            step_number=self._step_counter,
            role=role,
            content=content,
            risk_level=risk_level,
            related_finding=related_finding,
        )
        self._trace.append(step)
        if self.on_step:
            self.on_step(step.step_number, role, content[:200])

    def _compute_risk_score(self) -> int:
        """Compute dynamic risk score based on evidence collected."""
        if not self._evidences:
            return 0
        score = 0
        weights = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5}
        for ev in self._evidences:
            score += weights.get(ev.risk_level, 0)
        return min(score, 100)
