#!/usr/bin/env python3
"""Trusted GitHub control for a manual Pattern E2E run."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")


def api(method: str, path: str, payload: dict | None = None) -> Any:
    request = urllib.request.Request(
        "https://api.github.com" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"Authorization": "Bearer " + os.environ["GH_TOKEN"],
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
        return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub API {method} {path} returned HTTP {exc.code}") from exc


def status(repo: str, sha: str, state: str, description: str) -> None:
    api("POST", f"/repos/{repo}/statuses/{sha}", {
        "state": state, "context": "Pattern E2E", "description": description[:140],
        "target_url": os.environ["CI_RUN_URL"],
    })


def prepare() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    number = int(os.environ["CI_PR_NUMBER"])
    sha = os.environ["CI_HEAD_SHA"]
    if number <= 0 or not SHA.fullmatch(sha):
        raise RuntimeError("PR number and full expected SHA are required")
    pr = api("GET", f"/repos/{repo}/pulls/{number}")
    if pr["state"] != "open" or pr["head"]["sha"] != sha:
        raise RuntimeError("PR is closed or its head SHA changed")
    if pr["head"]["repo"]["full_name"] != repo:
        raise RuntimeError("Pattern E2E needs a reviewed branch in this repository")
    reviews = api("GET", f"/repos/{repo}/pulls/{number}/reviews?per_page=100")
    latest_review: dict[str, dict] = {}
    for review in reviews:
        if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest_review[review["user"]["login"]] = review
    if not any(review["state"] == "APPROVED" and review.get("commit_id") == sha
               for review in latest_review.values()):
        raise RuntimeError("the current PR head has no active approval")
    automatic = []
    # pull_request jobs can be attached to GitHub's current merge commit.
    # Check both that commit and the expected PR head.
    for commit in {sha, pr.get("merge_commit_sha")} - {None}:
        checks = api("GET", f"/repos/{repo}/commits/{commit}/check-runs?per_page=100")
        automatic.extend(check for check in checks.get("check_runs", [])
                         if check["name"] == "Deployment validation" and
                         check["app"]["slug"] == "github-actions")
    if not automatic or not any(check["conclusion"] == "success" for check in automatic):
        raise RuntimeError("Deployment validation has not passed at this SHA")
    # The reviewer starts this workflow from the default branch. The temporary
    # ref gives the Pattern operator a stable Git revision during the run.
    branch = f"ci/pattern-e2e/{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    api("POST", f"/repos/{repo}/git/refs", {"ref": "refs/heads/" + branch, "sha": sha})
    try:
        status(repo, sha, "pending", "Cluster test is running")
    except RuntimeError:
        api("DELETE", f"/repos/{repo}/git/refs/heads/{branch}")
        raise
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"sha={sha}\nbranch={branch}\n")
    print(f"Prepared PR {number} at {sha} on {branch}")


def finish() -> None:
    repo = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ.get("CI_HEAD_SHA", "")
    branch = os.environ.get("CI_TARGET_BRANCH", "")
    outcome = os.environ.get("CI_E2E_OUTCOME", "failure")
    result_path = os.environ.get("CI_E2E_RESULTS_PATH", "pattern-e2e-results/results.json")
    cleanup_verified = False
    try:
        with open(result_path, encoding="utf-8") as result_file:
            cleanup_verified = json.load(result_file).get("cleanup_verified") is True
    except FileNotFoundError:
        print("E2E result artifact is missing; retaining the temporary source ref")
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        print(f"E2E cleanup state is invalid ({type(exc).__name__}); "
              "retaining the temporary source ref")
    if branch and cleanup_verified:
        if not re.fullmatch(r"ci/pattern-e2e/[0-9]+-[0-9]+", branch):
            raise RuntimeError("temporary branch name is invalid")
        try:
            api("DELETE", f"/repos/{repo}/git/refs/heads/{branch}")
        except RuntimeError:
            if SHA.fullmatch(sha):
                status(repo, sha, "failure", "Temporary source ref cleanup failed")
            raise
    elif branch:
        print(f"Cluster cleanup is not verified; retaining {branch} for recovery")
    if SHA.fullmatch(sha):
        state = "success" if outcome == "success" and cleanup_verified else "failure"
        description = ("Cluster test passed" if state == "success" else
                       "Cluster test failed or cleanup is not verified")
        status(repo, sha, state, description)


if __name__ == "__main__":
    try:
        {"prepare": prepare, "finish": finish}[sys.argv[1]]()
    except (KeyError, ValueError, RuntimeError, urllib.error.URLError) as error:
        print(f"Pattern E2E control failed: {error}", file=sys.stderr)
        raise SystemExit(1)
