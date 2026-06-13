"""
ARNIE Playbook Validator
Pre-flight validation for generated Ansible playbooks.
Checks YAML syntax, Ansible structure, and common issues before approval.
"""

import re
import logging
from typing import Any, Dict, List

log = logging.getLogger("arnie.validator")

try:
    import yaml
except ImportError:
    yaml = None


class PlaybookValidator:
    """Validates generated Ansible playbooks before approval."""

    def validate(self, yaml_content: str) -> Dict[str, Any]:
        """Run all validation checks on a playbook."""
        issues: List[Dict[str, str]] = []
        warnings: List[Dict[str, str]] = []

        # 1. YAML syntax check
        yaml_valid = self._check_yaml(yaml_content, issues)

        # 2. Ansible structure check
        if yaml_valid:
            self._check_ansible_structure(yaml_content, issues, warnings)

        # 3. Security checks
        self._check_security(yaml_content, warnings)

        # 4. Best practices
        self._check_best_practices(yaml_content, warnings)

        valid = len(issues) == 0

        return {
            "valid": valid,
            "issues": issues,
            "warnings": warnings,
            "checks_run": [
                "yaml_syntax",
                "ansible_structure",
                "security_scan",
                "best_practices",
            ],
        }

    def _check_yaml(self, content: str, issues: List) -> bool:
        """Check if the content is valid YAML."""
        if yaml is None:
            return True  # Can't check without PyYAML
        try:
            docs = list(yaml.safe_load_all(content))
            if not docs or docs[0] is None:
                issues.append({
                    "severity": "error",
                    "check": "yaml_syntax",
                    "message": "YAML parsed but produced no documents",
                })
                return False
            return True
        except yaml.YAMLError as e:
            issues.append({
                "severity": "error",
                "check": "yaml_syntax",
                "message": f"Invalid YAML: {str(e)[:200]}",
            })
            return False

    def _check_ansible_structure(self, content: str, issues: List, warnings: List):
        """Check Ansible playbook structure."""
        if yaml is None:
            return
        try:
            docs = list(yaml.safe_load_all(content))
        except Exception:
            return

        for doc in docs:
            if doc is None:
                continue

            # Playbook should be a list of plays
            if isinstance(doc, list):
                for play in doc:
                    if not isinstance(play, dict):
                        continue
                    self._check_play(play, issues, warnings)
            elif isinstance(doc, dict):
                # Single play
                self._check_play(doc, issues, warnings)

    def _check_play(self, play: dict, issues: List, warnings: List):
        """Validate a single play."""
        # Must have hosts
        if "hosts" not in play:
            issues.append({
                "severity": "error",
                "check": "ansible_structure",
                "message": "Play missing 'hosts' field",
            })

        # Must have tasks or roles
        if "tasks" not in play and "roles" not in play:
            issues.append({
                "severity": "error",
                "check": "ansible_structure",
                "message": "Play has no 'tasks' or 'roles'",
            })

        # Check tasks have names
        tasks = play.get("tasks", [])
        if isinstance(tasks, list):
            for i, task in enumerate(tasks):
                if isinstance(task, dict) and "name" not in task:
                    warnings.append({
                        "severity": "warning",
                        "check": "ansible_structure",
                        "message": f"Task {i+1} has no 'name' field",
                    })

        # Should use connection: local for k8s
        if "connection" not in play:
            for task in (play.get("tasks") or []):
                if isinstance(task, dict):
                    modules = " ".join(str(k) for k in task.keys())
                    if "kubernetes" in modules or "k8s" in modules:
                        warnings.append({
                            "severity": "warning",
                            "check": "ansible_structure",
                            "message": "Play uses k8s modules but doesn't set 'connection: local'",
                        })
                        break

    def _check_security(self, content: str, warnings: List):
        """Check for security concerns."""
        lower = content.lower()

        # Hardcoded secrets
        if re.search(r'password:\s*["\'][^{]', content):
            warnings.append({
                "severity": "high",
                "check": "security",
                "message": "Possible hardcoded password detected — use vault or variables",
            })

        # Wildcard permissions
        if "'*'" in content or '"*"' in content:
            if "verbs" in lower or "apigroups" in lower or "resources" in lower:
                warnings.append({
                    "severity": "high",
                    "check": "security",
                    "message": "Wildcard (*) permissions detected — consider least-privilege",
                })

        # Privileged containers
        if "privileged: true" in lower:
            warnings.append({
                "severity": "high",
                "check": "security",
                "message": "Privileged container detected — review security implications",
            })

        # Host network
        if "hostnetwork: true" in lower:
            warnings.append({
                "severity": "medium",
                "check": "security",
                "message": "Host network mode detected",
            })

    def _check_best_practices(self, content: str, warnings: List):
        """Check Ansible best practices."""
        # gather_facts for localhost plays
        if "hosts: localhost" in content and "gather_facts" not in content:
            warnings.append({
                "severity": "info",
                "check": "best_practices",
                "message": "Consider adding 'gather_facts: false' for localhost plays",
            })

        # No tags
        if "tags:" not in content:
            warnings.append({
                "severity": "info",
                "check": "best_practices",
                "message": "No tags defined — consider adding tags for selective execution",
            })
