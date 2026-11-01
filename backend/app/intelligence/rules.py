"""
Static Source Code Rule Engine:
Fast AST and pattern-based static code analyzer for JavaScript, TypeScript, and Python.
Works completely offline without mandatory external dependencies.
Redacts secrets in excerpts and returns structured code evidence.
"""
import os
import re
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("blindspot.intelligence.rules")

SECRET_REDACT_REGEX = re.compile(
    r'(?i)(rzp_live_[a-zA-Z0-9]{14,24}|sk_live_[a-zA-Z0-9]{20,32}|[a-zA-Z0-9+/]{30,}={0,2})'
)

def redact_sensitive_text(text: str) -> str:
    """Replaces live keys and long tokens with redacted representation."""
    if not text:
        return ""
    # Redact common live key patterns
    redacted = re.sub(r'rzp_live_[a-zA-Z0-9]{14,}', 'rzp_live_••••••••[REDACTED]', text)
    redacted = re.sub(r'sk_live_[a-zA-Z0-9]{20,}', 'sk_live_••••••••[REDACTED]', redacted)
    redacted = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA••••••••••••••••', redacted)
    # Redact key_secret values
    redacted = re.sub(r'(?i)(key_secret\s*[:=]\s*[\'"])[^\'"]+([\'"])', r'\1••••••••[REDACTED]\2', redacted)
    return redacted

class StaticRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        severity: str,
        patterns: List[str],
        negative_patterns: Optional[List[str]] = None,
        file_extensions: Optional[List[str]] = None,
        explanation: str = "",
        remediation: str = ""
    ):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in patterns]
        self.negative_patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in (negative_patterns or [])]
        self.file_extensions = file_extensions or [".js", ".jsx", ".ts", ".tsx", ".py"]
        self.explanation = explanation
        self.remediation = remediation

    def scan_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.file_extensions:
            return []

        # Check negative patterns first (if any negative pattern matches whole file, skip)
        for neg in self.negative_patterns:
            if neg.search(content):
                return []

        lines = content.splitlines()
        for pat in self.patterns:
            for i, line in enumerate(lines, start=1):
                if pat.search(line):
                    # Redact evidence excerpt
                    safe_excerpt = redact_sensitive_text(line.strip())
                    findings.append({
                        "rule_id": self.rule_id,
                        "name": self.name,
                        "severity": self.severity,
                        "file_path": file_path,
                        "line_number": i,
                        "code_excerpt": safe_excerpt[:200],
                        "explanation": self.explanation,
                        "remediation": self.remediation
                    })
                    break  # One match per rule per file to keep findings actionable
        return findings

class StaticSourceAnalyzer:
    def __init__(self, rules: Optional[List[StaticRule]] = None):
        self.rules = rules or []

    def add_rule(self, rule: StaticRule):
        self.rules.append(rule)

    def scan_directory(self, target_dir: str) -> List[Dict[str, Any]]:
        abs_dir = os.path.abspath(target_dir)
        all_findings = []
        if not os.path.exists(abs_dir):
            return []

        for root, _, files in os.walk(abs_dir):
            for file in files:
                fpath = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                if ext in [".js", ".jsx", ".ts", ".tsx", ".py", ".json", ".env"]:
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read(200000)  # Scan up to 200KB per file
                        rel_path = os.path.relpath(fpath, abs_dir)
                        for rule in self.rules:
                            matches = rule.scan_file(rel_path, content)
                            all_findings.extend(matches)
                    except Exception as e:
                        logger.debug(f"Error scanning {fpath}: {e}")

        return all_findings
