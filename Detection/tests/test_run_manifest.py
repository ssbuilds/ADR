"""Tests for privacy-safe detector run provenance."""

import hashlib
import json
import subprocess
from pathlib import Path

import run_manifest
from run_manifest import collect_run_manifest


def _task(results_dir: Path, task_id: int, content: str = "{}") -> Path:
    task_dir = results_dir / f"task_{task_id:03d}"
    workspace = task_dir / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "claude_conversation.json").write_text(content)
    return task_dir


def _collect(detection_root: Path, results_dir: Path, task_dirs, **overrides):
    arguments = {
        "detection_root": detection_root,
        "results_dir": results_dir,
        "benchmark_type": "adr_bench",
        "task_dirs": task_dirs,
        "effective_labels": {"task_001": False, "task_002": True},
        "resolved_concurrency": 7,
    }
    arguments.update(overrides)
    return collect_run_manifest(**arguments)


def test_hashes_selected_conversations_and_labels_in_task_order(tmp_path: Path):
    detection_root = tmp_path / "Detection"
    detection_root.mkdir()
    results = tmp_path / "results-secret-name"
    second = _task(results, 2, '{"message":"second"}')
    first = _task(results, 1, '{"message":"first"}')

    manifest = _collect(detection_root, results, [second, first])

    assert manifest["selected_task_ids"] == [1, 2]
    conversations = manifest["inputs"]["conversations"]
    expected = [
        {"task_id": task_id, "sha256": hashlib.sha256(content.encode()).hexdigest()}
        for task_id, content in ((1, '{"message":"first"}'), (2, '{"message":"second"}'))
    ]
    expected_hash = hashlib.sha256(
        json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert conversations["aggregate_sha256"] == expected_hash
    assert conversations["count"] == 2
    assert manifest["inputs"]["effective_labels"]["count"] == 2
    assert manifest["resolved_concurrency"] == 7


def test_agentdojo_hashes_actual_ground_truth_file(tmp_path: Path):
    detection_root = tmp_path / "Detection"
    detection_root.mkdir()
    results = tmp_path / "run"
    task = _task(results, 1)
    ground_truth = b'{"task_001":{"is_malicious":true}}'
    (results / "ground_truth.json").write_bytes(ground_truth)

    manifest = _collect(
        detection_root,
        results,
        [task],
        benchmark_type="agentdojo",
        effective_labels={"task_001": True},
    )

    artifacts = manifest["inputs"]["artifacts"]
    assert artifacts["agentdojo_ground_truth"] == hashlib.sha256(ground_truth).hexdigest()
    assert artifacts["tasks"] is None


def test_missing_inputs_and_metadata_are_nonfatal_and_explicit(tmp_path: Path, monkeypatch):
    detection_root = tmp_path / "Detection"
    detection_root.mkdir()
    results = tmp_path / "run"
    task = results / "task_001"
    task.mkdir(parents=True)
    monkeypatch.setattr(run_manifest, "_git_output", lambda *args: None)

    manifest = _collect(detection_root, results, [task], effective_labels={})

    assert manifest["source"] == {"commit": None, "dirty": None}
    assert manifest["inputs"]["conversations"]["missing_task_ids"] == [1]
    assert manifest["inputs"]["effective_labels"]["missing_task_ids"] == [1]
    assert manifest["inputs"]["artifacts"]["config_detector"] is None
    assert manifest["inputs"]["artifacts"]["uv_lock"] is None


def test_git_calls_are_bounded_and_report_clean_or_dirty(tmp_path: Path):
    repo = tmp_path / "repo"
    detection_root = repo / "Detection"
    detection_root.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    (detection_root / "tracked.txt").write_text("clean")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "initial"], check=True)
    results = tmp_path / "run"
    task = _task(results, 1)

    clean = _collect(detection_root, results, [task])
    assert clean["source"]["commit"]
    assert clean["source"]["dirty"] is False

    (detection_root / "untracked.txt").write_text("dirty")
    untracked = _collect(detection_root, results, [task])
    assert untracked["source"]["dirty"] is True
    (detection_root / "untracked.txt").unlink()

    (detection_root / "tracked.txt").write_text("dirty")
    dirty = _collect(detection_root, results, [task])
    assert dirty["source"]["dirty"] is True


def test_manifest_excludes_paths_basenames_and_host_identifiers(tmp_path: Path):
    detection_root = tmp_path / "Detection"
    detection_root.mkdir()
    results = tmp_path / "customer-secret-benchmark"
    task = _task(results, 1)

    serialized = json.dumps(_collect(detection_root, results, [task]))

    assert "customer-secret-benchmark" not in serialized
    assert str(tmp_path) not in serialized
    assert "hostname" not in serialized
    assert "platform" not in serialized
    assert "path" not in serialized


def test_git_commands_have_a_short_timeout(tmp_path: Path, monkeypatch):
    calls = []

    def fake_run(*args, **kwargs):
        calls.append(kwargs)
        return subprocess.CompletedProcess(args[0], 0, stdout="abc123\n", stderr="")

    monkeypatch.setattr(run_manifest.subprocess, "run", fake_run)
    assert run_manifest._git_output(tmp_path, "rev-parse", "HEAD") == "abc123"
    assert calls[0]["timeout"] == run_manifest._GIT_TIMEOUT_SECONDS == 2
