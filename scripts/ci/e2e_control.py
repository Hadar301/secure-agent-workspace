#!/usr/bin/env python3
"""Trusted GitHub control for a manual Pattern E2E run."""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
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
    pr_input = os.environ.get("CI_PR_NUMBER", "").strip()
    source_branch = os.environ.get("CI_SOURCE_BRANCH", "").strip()
    if bool(pr_input) == bool(source_branch):
        raise RuntimeError("provide exactly one PR number or branch name")

    merge_sha = None
    if pr_input:
        try:
            number = int(pr_input)
        except ValueError as exc:
            raise RuntimeError("PR number must be a positive integer") from exc
        if number <= 0:
            raise RuntimeError("PR number must be a positive integer")
        pr = api("GET", f"/repos/{repo}/pulls/{number}")
        if pr.get("state") != "open":
            raise RuntimeError("PR is not open")
        base = pr.get("base")
        base_repo = base.get("repo") if isinstance(base, dict) else None
        base_name = base_repo.get("full_name") if isinstance(base_repo, dict) else None
        if not isinstance(base_name, str) or base_name.lower() != repo.lower():
            raise RuntimeError("PR does not target this repository")
        head = pr.get("head", {})
        sha = head.get("sha") if isinstance(head, dict) else None
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise RuntimeError("PR head SHA is invalid")
        source_repo = head.get("repo")
        source_name = (source_repo.get("full_name")
                       if isinstance(source_repo, dict) else None)
        if not isinstance(source_name, str) or not source_name:
            raise RuntimeError("PR source repository is unavailable")
        merge_sha = pr.get("merge_commit_sha")
        label = f"PR #{number}"
        target_url = f"{os.environ['GITHUB_SERVER_URL']}/{repo}/pull/{number}"
    else:
        encoded_branch = urllib.parse.quote(source_branch, safe="")
        ref = api("GET", f"/repos/{repo}/git/ref/heads/{encoded_branch}")
        obj = ref.get("object") if isinstance(ref, dict) else None
        sha = obj.get("sha") if isinstance(obj, dict) else None
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            raise RuntimeError("branch head SHA is invalid")
        if isinstance(obj, dict) and obj.get("type") != "commit":
            raise RuntimeError("branch does not point to a commit")
        source_name = repo
        label = f"branch {source_branch}"
        encoded_url_branch = urllib.parse.quote(source_branch, safe="/")
        target_url = f"{os.environ['GITHUB_SERVER_URL']}/{repo}/tree/{encoded_url_branch}"

    automatic = []
    # pull_request jobs can be attached to GitHub's current merge commit.
    # For PRs, check both that commit and the latest PR head from the API.
    for commit in {sha, merge_sha} - {None}:
        checks = api("GET", f"/repos/{repo}/commits/{commit}/check-runs?per_page=100")
        check_runs = checks.get("check_runs") if isinstance(checks, dict) else None
        if not isinstance(check_runs, list):
            raise RuntimeError("GitHub returned an invalid check-runs response")
        automatic.extend(check for check in check_runs
                         if check["name"] == "Deployment validation" and
                         check.get("app", {}).get("slug") == "github-actions")
    if not automatic or not any(check["conclusion"] == "success" for check in automatic):
        raise RuntimeError("Deployment validation has not passed at this SHA")

    # The environment approval is the trust gate before the cluster job gets
    # credentials. The temporary ref pins the PR commit for the full run.
    branch = f"ci/pattern-e2e/{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
    api("POST", f"/repos/{repo}/git/refs", {"ref": "refs/heads/" + branch, "sha": sha})
    try:
        status(repo, sha, "pending", "Pattern E2E is queued for cluster test")
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"sha={sha}\nbranch={branch}\nlabel={label}\nurl={target_url}\n")
    except RuntimeError:
        api("DELETE", f"/repos/{repo}/git/refs/heads/{branch}")
        raise
    print(f"Prepared {label} from {source_name} at {sha} on {branch}")


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
