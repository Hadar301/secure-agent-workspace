"""Cache tests execute Python helper behavior and stay in both Python jobs."""
import subprocess

import pytest
import yaml

import helm_cache


@pytest.fixture
def render_command(tmp_path, monkeypatch):
    chart = tmp_path / "chart"
    chart.mkdir()
    (chart / "Chart.yaml").write_text("name: sample\nversion: 1.0.0\n")
    values = tmp_path / "values.yaml"
    values.write_text("replicas: 1\n")
    calls = []

    def render(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "spec:\n  replicas: 1\n", "")

    monkeypatch.setattr(helm_cache.subprocess, "run", render)
    return ["helm", "template", "release", str(chart), "-n", "namespace", "-f", str(values)], calls


def test_repeated_render_has_independent_results_and_documents(render_command):
    command, calls = render_command
    first = helm_cache.run_helm(command)
    document = yaml.safe_load(first.stdout)
    document["spec"]["replicas"] = 99
    first.stdout = "changed"
    second = helm_cache.run_helm(command)
    assert yaml.safe_load(second.stdout) == {"spec": {"replicas": 1}}
    assert len(calls) == 1
    # One render lifecycle: change one input at a time, then render again.
    from pathlib import Path
    Path(command[-1]).write_text("replicas: 2\n")
    helm_cache.run_helm(command)
    assert len(calls) == 2, "changed values must render again"
    (Path(command[3]) / "Chart.yaml").write_text("name: changed\nversion: 1.0.0\n")
    helm_cache.run_helm(command)
    assert len(calls) == 3, "changed chart must render again"
    command[2] = "other"
    helm_cache.run_helm(command)
    assert len(calls) == 4, "changed release must render again"
    command[5] = "other"
    helm_cache.run_helm(command)
    assert len(calls) == 5, "changed namespace must render again"
    command.extend(["--set", "replicas=2"])
    helm_cache.run_helm(command)
    assert len(calls) == 6, "changed arguments must render again"



def test_failed_render_is_retried(render_command, monkeypatch):
    command, _ = render_command
    outcomes = iter([1, 0])

    def render(command, **kwargs):
        return subprocess.CompletedProcess(command, next(outcomes), "", "failed")

    monkeypatch.setattr(helm_cache.subprocess, "run", render)
    assert helm_cache.run_helm(command).returncode == 1
    assert helm_cache.run_helm(command).returncode == 0
