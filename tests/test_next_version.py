import importlib.util
import subprocess
from pathlib import Path

import pytest

_path = Path(__file__).resolve().parent.parent / "scripts" / "next_version.py"
_spec = importlib.util.spec_from_file_location("next_version", _path)
nv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nv)


@pytest.mark.parametrize("messages,expected", [
    (["fix: handle empty folder"], "1.4.3"),
    (["docs: typo", "chore: deps"], "1.4.3"),
    (["fix: x", "feat: add search"], "1.5.0"),
    (["feat(imap): add flags"], "1.5.0"),
    (["refactor!: drop proxy mode"], "2.0.0"),
    (["fix: x\n\nBREAKING CHANGE: env var renamed"], "2.0.0"),
    (["Feat: capitalized"], "1.5.0"),
    (["featuring something: not a feat"], "1.4.3"),
])
def test_auto_bump(messages, expected):
    assert nv.next_version("1.4.2", messages) == expected


def test_breaking_change_below_1_0_bumps_minor():
    assert nv.next_version("0.3.1", ["feat!: new config format"]) == "0.4.0"


def test_explicit_bump_overrides_and_can_reach_1_0():
    assert nv.next_version("0.9.4", ["fix: x"], bump="major") == "1.0.0"
    assert nv.next_version("1.2.3", ["feat: x"], bump="patch") == "1.2.4"


def test_first_release_and_nothing_to_release():
    assert nv.next_version(None, ["anything"]) == nv.INITIAL_VERSION
    assert nv.next_version("1.0.0", []) is None
    assert nv.next_version("1.0.0", [], bump="patch") == "1.0.1"  # manual rerun


def test_invalid_previous_version():
    with pytest.raises(ValueError):
        nv.next_version("1.2", ["fix: x"])


def test_against_a_real_git_repo(tmp_path, monkeypatch):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("commit", "-q", "--allow-empty", "-m", "chore: init")
    git("tag", "v0.2.0")
    git("tag", "not-a-version")
    git("commit", "-q", "--allow-empty", "-m", "feat: something")
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "out"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    assert nv.main([]) == 0
    assert output.read_text() == "previous=v0.2.0\nversion=0.3.0\ntag=v0.3.0\nrelease=true\n"
