#!/usr/bin/env python3
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

class TestWorkflowActionPinning(unittest.TestCase):
    def test_release_omawarden_actions_pinned(self):
        workflow = REPO_ROOT / ".github" / "workflows" / "release-omawarden.yml"
        self.assertTrue(workflow.exists(), f"{workflow} does not exist")
        content = workflow.read_text(encoding="utf-8")

        # Find all `uses: ...` lines
        uses_matches = re.findall(r'uses:\s+([^#\n\s]+)', content)
        for action in uses_matches:
            with self.subTest(action=action):
                self.assertIn('@', action, f"Action missing version tag: {action}")
                _, ref = action.split('@', 1)
                self.assertTrue(
                    re.match(r'^[a-f0-9]{40}$', ref),
                    f"Action {action} in release-omawarden.yml must be pinned to a 40-char commit SHA, got: {ref}"
                )

        # Check cross installation git revision
        cross_match = re.search(r'cargo install cross\s+([^\n]+)', content)
        self.assertIsNotNone(cross_match, "cargo install cross command not found")
        cross_cmd = cross_match.group(1)
        self.assertIn('--rev', cross_cmd, "cargo install cross must specify --rev <commit-sha>")
        rev_match = re.search(r'--rev\s+([a-f0-9]{40})', cross_cmd)
        self.assertIsNotNone(rev_match, f"cargo install cross --rev must be 40-char SHA: {cross_cmd}")

    def test_release_plugin_actions_pinned(self):
        workflow = REPO_ROOT / ".github" / "workflows" / "release-plugin.yml"
        self.assertTrue(workflow.exists(), f"{workflow} does not exist")
        content = workflow.read_text(encoding="utf-8")

        uses_matches = re.findall(r'uses:\s+([^#\n\s]+)', content)
        for action in uses_matches:
            with self.subTest(action=action):
                self.assertIn('@', action, f"Action missing version tag: {action}")
                _, ref = action.split('@', 1)
                self.assertTrue(
                    re.match(r'^[a-f0-9]{40}$', ref),
                    f"Action {action} in release-plugin.yml must be pinned to a 40-char commit SHA, got: {ref}"
                )

    def test_all_workflows_pinned_to_sha(self):
        workflows_dir = REPO_ROOT / ".github" / "workflows"
        for wf in workflows_dir.glob("*.yml"):
            content = wf.read_text(encoding="utf-8")
            uses_matches = re.findall(r'uses:\s+([^#\n\s]+)', content)
            for action in uses_matches:
                with self.subTest(workflow=wf.name, action=action):
                    self.assertIn('@', action, f"Action {action} in {wf.name} missing '@'")
                    _, ref = action.split('@', 1)
                    self.assertTrue(
                        re.match(r'^[a-f0-9]{40}$', ref),
                        f"Action {action} in {wf.name} must be pinned to a 40-char commit SHA, got: {ref}"
                    )

if __name__ == "__main__":
    unittest.main()
