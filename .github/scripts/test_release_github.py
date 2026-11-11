import base64
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error


spec = importlib.util.spec_from_file_location(
    "release_github", Path(__file__).with_name("release-github.py")
)
release = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = release
spec.loader.exec_module(release)

SHA = "a" * 40
OTHER = "b" * 40
PLAN = release.Plan(SHA, "0.10.0", "Release notes.")


def run(number, status="completed", conclusion="success"):
    return {
        "id": number,
        "head_sha": SHA,
        "event": "push",
        "head_branch": "main",
        "created_at": f"2026-11-{number:02d}T00:00:00Z",
        "run_attempt": 1,
        "status": status,
        "conclusion": conclusion,
        "html_url": f"https://github.com/example/repo/actions/runs/{number}",
    }


def published(**overrides):
    return {
        "tag_name": PLAN.tag,
        "draft": False,
        "prerelease": False,
        "html_url": f"https://github.com/example/repo/releases/tag/{PLAN.tag}",
        **overrides,
    }


class FakeGitHub(release.GitHub):
    def __init__(self):
        super().__init__("example/repo", "unused")
        self.responses = {
            "commits/main": {"sha": SHA},
            "commits/v0.10.0": {"sha": SHA},
            f"commits/{SHA}": {"sha": SHA},
            "git/ref/tags/v0.10.0": release.ApiError(404, "Not Found"),
            "releases/tags/v0.10.0": release.ApiError(404, "Not Found"),
            "releases?per_page=100&page=1": [],
        }
        self.writes = []
        for workflow in ("rust.yaml", "nix.yml"):
            self.responses[f"actions/workflows/{workflow}/runs?head_sha={SHA}&event=push&branch=main&per_page=100"] = {
                "workflow_runs": [run(11)]
            }
        for path, content in {
            "Cargo.toml": '[workspace.package]\nversion = "0.10.0"\n',
            "CHANGELOG.md": "# Changes\n\n## 0.10.0\n\nRelease notes.\n\n## 0.9.0\n\nOld.\n",
        }.items():
            self.responses[f"contents/{path}?ref={SHA}"] = {
                "type": "file",
                "encoding": "base64",
                "content": base64.b64encode(content.encode()).decode(),
            }

    def request(self, path, data=None):
        if data is not None:
            self.writes.append((path, data))
            if path == "git/refs":
                self.responses["git/ref/tags/v0.10.0"] = {
                    "object": {"type": "commit", "sha": data["sha"]}
                }
                return self.responses["git/ref/tags/v0.10.0"]
            if path == "releases":
                self.responses["releases/tags/v0.10.0"] = published()
                return self.responses["releases/tags/v0.10.0"]
            raise AssertionError(f"Unexpected mutation: {path}")
        response = self.responses[path]
        if isinstance(response, Exception):
            raise response
        return response


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()

    def test_old_tag_plan_reads_metadata_without_requiring_automation_at_tag(self):
        plan = release.plan_release(self.api, "v0.10.0")
        self.assertEqual(plan, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_new_release_creates_one_exact_tag_and_release_then_is_idempotent(self):
        plan = release.plan_release(self.api, "main")
        release.publish(self.api, plan)
        self.assertEqual(self.api.writes[0], ("git/refs", {"ref": "refs/tags/v0.10.0", "sha": SHA}))
        self.assertEqual(self.api.writes[1][1]["body"], "Release notes.")
        self.assertEqual(self.api.writes[1][1]["target_commitish"], SHA)
        self.assertFalse(self.api.writes[1][1]["draft"])
        release.publish(self.api, plan)
        self.assertEqual(len(self.api.writes), 2)

    def test_branch_movement_cannot_change_pinned_publish_commit(self):
        plan = release.plan_release(self.api, "main")
        self.api.responses["commits/main"] = {"sha": OTHER}
        pinned = release.plan_release(self.api, plan.sha)
        release.publish(self.api, pinned)
        self.assertEqual(self.api.writes[0][1]["sha"], SHA)

    def test_release_api_failure_keeps_tag_and_can_resume(self):
        original = self.api.request

        def failing(path, data=None):
            if path == "releases" and data is not None:
                raise release.ApiError(503, "Service unavailable")
            return original(path, data)

        with patch.object(self.api, "request", side_effect=failing):
            with self.assertRaises(release.ApiError):
                release.publish(self.api, PLAN)
        self.assertEqual(release.tag_commit(self.api, PLAN.tag), SHA)
        release.publish(self.api, PLAN)
        self.assertEqual([path for path, _ in self.api.writes], ["git/refs", "releases"])

    def test_published_annotated_tag_is_noop(self):
        self.api.responses["git/ref/tags/v0.10.0"] = {"object": {"type": "tag", "sha": OTHER}}
        self.api.responses[f"git/tags/{OTHER}"] = {"object": {"type": "commit", "sha": SHA}}
        self.api.responses["releases/tags/v0.10.0"] = published()
        release.publish(self.api, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_wrong_tag_commit_fails_without_mutation(self):
        self.api.responses["git/ref/tags/v0.10.0"] = {"object": {"type": "commit", "sha": OTHER}}
        with self.assertRaisesRegex(release.ReleaseError, "refusing to move"):
            release.publish(self.api, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_existing_tag_recovers_release_creation_after_partial_failure(self):
        self.api.responses["git/ref/tags/v0.10.0"] = {"object": {"type": "commit", "sha": SHA}}
        release.publish(self.api, PLAN)
        self.assertEqual([path for path, _ in self.api.writes], ["releases"])

    def test_draft_omitted_by_tag_lookup_is_never_published(self):
        self.api.responses["git/ref/tags/v0.10.0"] = {"object": {"type": "commit", "sha": SHA}}
        self.api.responses["releases?per_page=100&page=1"] = [published(draft=True)]
        with self.assertRaisesRegex(release.ReleaseError, "is a draft"):
            release.publish(self.api, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_existing_release_without_tag_is_not_retargeted(self):
        self.api.responses["releases/tags/v0.10.0"] = published()
        with self.assertRaisesRegex(release.ReleaseError, "without its Git tag"):
            release.publish(self.api, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_missing_failed_pending_and_newer_failed_ci_block_release(self):
        path = f"actions/workflows/rust.yaml/runs?head_sha={SHA}&event=push&branch=main&per_page=100"
        for runs in [[], [run(11, conclusion="failure")], [run(11, "in_progress", None)], [run(10), run(11, conclusion="failure")]]:
            with self.subTest(runs=runs):
                self.api.responses[path] = {"workflow_runs": runs}
                with self.assertRaises(release.ReleaseError):
                    release.plan_release(self.api, "main")
        self.assertEqual(self.api.writes, [])

    def test_ci_must_match_exact_sha(self):
        path = f"actions/workflows/nix.yml/runs?head_sha={SHA}&event=push&branch=main&per_page=100"
        self.api.responses[path] = {"workflow_runs": [{**run(11), "head_sha": OTHER}]}
        with self.assertRaisesRegex(release.ReleaseError, "No nix.yml CI run"):
            release.plan_release(self.api, "main")

    def test_pull_request_and_non_main_push_runs_do_not_qualify(self):
        path = f"actions/workflows/nix.yml/runs?head_sha={SHA}&event=push&branch=main&per_page=100"
        for extra in ({"event": "pull_request"}, {"head_branch": "feature"}):
            with self.subTest(extra=extra):
                self.api.responses[path] = {"workflow_runs": [{**run(11), **extra}]}
                with self.assertRaisesRegex(release.ReleaseError, "No nix.yml CI run"):
                    release.plan_release(self.api, "main")

    def test_only_404_is_treated_as_missing(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                self.api.responses["git/ref/tags/v0.10.0"] = release.ApiError(status, "Failure")
                with self.assertRaises(release.ApiError):
                    release.publish(self.api, PLAN)
        self.assertEqual(self.api.writes, [])

    def test_changelog_requires_one_nonempty_version_section(self):
        for text in ("## 0.9.0\nold", "## 0.10.0\n\n## 0.9.0\nold", "## 0.10.0\none\n## 0.10.0\ntwo"):
            with self.subTest(text=text), self.assertRaises(release.ReleaseError):
                release.changelog_section(text, "0.10.0")

    def test_http_error_does_not_leak_token(self):
        api = release.GitHub("example/repo", "SECRET")
        error = urllib.error.HTTPError("https://api.github.com/", 403, "Forbidden", {}, None)
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(release.ApiError) as raised:
                api.request("releases")
        self.assertNotIn("SECRET", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
