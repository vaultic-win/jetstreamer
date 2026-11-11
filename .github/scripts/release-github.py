#!/usr/bin/env python3
"""Publish one GitHub source release from a versioned, CI-verified commit."""

import argparse
import base64
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


class ReleaseError(Exception):
    pass


class ApiError(ReleaseError):
    def __init__(self, status, message):
        super().__init__(f"GitHub API returned HTTP {status}: {message}")
        self.status = status


class GitHub:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ReleaseError("Invalid repository name")
        self.repository = repository
        self.token = token

    def request(self, path, data=None):
        url = f"https://api.github.com/repos/{self.repository}/{path}"
        request = urllib.request.Request(
            url,
            data=json.dumps(data).encode() if data is not None else None,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
                "User-Agent": "jetstreamer-github-release",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            try:
                message = json.load(error).get("message", error.reason)
            except (ValueError, AttributeError):
                message = error.reason
            raise ApiError(error.code, message) from None

    def optional(self, path):
        try:
            return self.request(path)
        except ApiError as error:
            if error.status == 404:
                return None
            raise

    def text(self, path, sha):
        file = self.request(f"contents/{path}?ref={sha}")
        if file.get("encoding") != "base64" or file.get("type") != "file":
            raise ReleaseError(f"Expected a source file at {path}")
        return base64.b64decode(file["content"]).decode("utf-8")


@dataclass(frozen=True)
class Plan:
    sha: str
    version: str
    notes: str

    @property
    def tag(self):
        return f"v{self.version}"

    @property
    def prerelease(self):
        return "-" in self.version


def changelog_section(changelog, version):
    heading = f"## {version}"
    lines = changelog.splitlines()
    matches = [i for i, line in enumerate(lines) if line.strip() == heading]
    if len(matches) != 1:
        raise ReleaseError(f"CHANGELOG.md needs exactly one '{heading}' section")
    body = []
    for line in lines[matches[0] + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    notes = "\n".join(body).strip()
    if not notes:
        raise ReleaseError(f"CHANGELOG.md has no release notes for {version}")
    return notes


def require_ci(api, sha):
    for workflow in ("rust.yaml", "nix.yml"):
        runs = api.request(
            f"actions/workflows/{workflow}/runs?head_sha={sha}&event=push&branch=main&per_page=100"
        )["workflow_runs"]
        runs = [
            run
            for run in runs
            if run.get("head_sha") == sha
            and run.get("event") == "push"
            and run.get("head_branch") == "main"
        ]
        if not runs:
            raise ReleaseError(f"No {workflow} CI run exists for {sha}")
        latest = max(runs, key=lambda run: (run["created_at"], run["id"], run["run_attempt"]))
        if latest["status"] != "completed" or latest["conclusion"] != "success":
            raise ReleaseError(
                f"Latest {workflow} run must pass for {sha}: "
                f"{latest['html_url']} ({latest['status']}/{latest['conclusion']})"
            )


def plan_release(api, ref):
    commit = api.request(f"commits/{urllib.parse.quote(ref, safe='')}")
    sha = commit["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ReleaseError("GitHub did not resolve the input to a commit SHA")
    manifest = tomllib.loads(api.text("Cargo.toml", sha))
    version = manifest["workspace"]["package"]["version"]
    if not isinstance(version, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?",
        version,
    ):
        raise ReleaseError("Workspace version must be a release version such as 0.10.0")
    plan = Plan(sha, version, changelog_section(api.text("CHANGELOG.md", sha), version))
    require_ci(api, sha)
    return plan


def tag_commit(api, tag):
    ref = api.optional(f"git/ref/tags/{urllib.parse.quote(tag, safe='')}")
    if ref is None:
        return None
    obj = ref["object"]
    # Accept lightweight and annotated tags, including nested annotated tags.
    for _ in range(20):
        if obj["type"] == "commit":
            return obj["sha"]
        if obj["type"] != "tag":
            break
        obj = api.request(f"git/tags/{obj['sha']}")["object"]
    raise ReleaseError(f"Tag {tag} does not resolve to a commit")


def find_release(api, tag):
    release = api.optional(f"releases/tags/{tag}")
    if release is not None:
        return release
    # The by-tag endpoint can omit drafts. An existing draft must never be
    # replaced or published implicitly by this source-release workflow.
    page = 1
    while True:
        releases = api.request(f"releases?per_page=100&page={page}")
        matches = [release for release in releases if release["tag_name"] == tag]
        if len(matches) > 1:
            raise ReleaseError(f"Multiple releases exist for {tag}")
        if matches:
            return matches[0]
        if len(releases) < 100:
            return None
        page += 1


def check_existing(api, plan):
    tagged = tag_commit(api, plan.tag)
    if tagged is not None and tagged != plan.sha:
        raise ReleaseError(f"Tag {plan.tag} already points to {tagged}; refusing to move it")
    release = find_release(api, plan.tag)
    if release is not None:
        if tagged is None:
            raise ReleaseError(f"Release {plan.tag} exists without its Git tag")
        if release["draft"]:
            raise ReleaseError(f"Release {plan.tag} is a draft; publish or remove it manually")
        if release["prerelease"] != plan.prerelease:
            raise ReleaseError(f"Release {plan.tag} has an unexpected prerelease status")
    return tagged, release


def publish(api, plan):
    tagged, release = check_existing(api, plan)
    if release is not None:
        print(f"Already released: {release['html_url']}")
        return release
    if tagged is None:
        try:
            api.request("git/refs", {"ref": f"refs/tags/{plan.tag}", "sha": plan.sha})
        except ApiError as error:
            # A concurrent publisher may create the tag. Accept only the exact SHA.
            if error.status != 422 or tag_commit(api, plan.tag) != plan.sha:
                raise
    # Recheck before publication so existing tags are never silently retargeted.
    tagged, release = check_existing(api, plan)
    if tagged != plan.sha:
        raise ReleaseError(f"Tag {plan.tag} changed before publication")
    if release is not None:
        print(f"Already released: {release['html_url']}")
        return release
    release = api.request(
        "releases",
        {
            "tag_name": plan.tag,
            "target_commitish": plan.sha,
            "name": f"Jetstreamer {plan.version}",
            "body": plan.notes,
            "draft": False,
            "prerelease": plan.prerelease,
            "make_latest": "false" if plan.prerelease else "legacy",
        },
    )
    print(f"Published: {release['html_url']}")
    return release


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "publish"))
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    api = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
    plan = plan_release(api, args.ref)
    check_existing(api, plan)
    print(f"{plan.tag}: {plan.sha}")
    if args.mode == "publish":
        publish(api, plan)
    elif output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a") as stream:
            stream.write(f"sha={plan.sha}\n")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a") as stream:
            stream.write(f"Release `{plan.tag}` from `{plan.sha}`.\n")


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, KeyError, ValueError, OSError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        sys.exit(1)
