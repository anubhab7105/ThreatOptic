
from __future__ import annotations

import os

import pytest

from app.config import resolve_env_files


@pytest.fixture
def tree(tmp_path):

    root = tmp_path / "repo"
    backend = root / "backend"
    (backend / "app").mkdir(parents=True)
    return root, backend


def test_root_env_is_found_when_it_is_the_only_file(tree):
    _, backend = tree
    (backend.parent / ".env").write_text("APP_ENV=development\n")
    assert resolve_env_files(str(backend)) == [str(backend.parent / ".env")]


def test_backend_env_is_found_when_it_is_the_only_file(tree):
    _, backend = tree
    (backend / ".env").write_text("APP_ENV=development\n")
    assert resolve_env_files(str(backend)) == [str(backend / ".env")]


def test_backend_env_takes_precedence_over_root(tree):

    _, backend = tree
    (backend / ".env").write_text("APP_ENV=development\n")
    (backend.parent / ".env").write_text("APP_ENV=production\n")
    assert resolve_env_files(str(backend))[0] == str(backend / ".env")


def test_order_is_backend_then_root(tree):

    _, backend = tree
    (backend / ".env").write_text("A=1\n")
    (backend.parent / ".env").write_text("A=2\n")
    assert resolve_env_files(str(backend)) == [
        str(backend / ".env"),
        str(backend.parent / ".env"),
    ]


def test_no_files_yields_empty_list_not_an_error(tree):

    _, backend = tree
    assert resolve_env_files(str(backend)) == []


def test_a_directory_named_env_is_not_treated_as_a_file(tree):
    _, backend = tree
    (backend / ".env").mkdir()
    assert resolve_env_files(str(backend)) == []





def test_resolution_is_relative_to_the_module_not_the_cwd():

    import app.config as cfg

    resolved = resolve_env_files(cfg._backend_dir)
    expected_candidates = {
        os.path.join(cfg._backend_dir, ".env"),
        os.path.join(os.path.dirname(cfg._backend_dir), ".env"),
    }
    assert set(resolved) <= expected_candidates
    for path in resolved:
        assert os.path.isabs(path)


def test_every_resolved_file_is_gitignored():


    repo = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    gitignore = os.path.join(repo, ".gitignore")
    if not os.path.isfile(gitignore):
        pytest.skip("no .gitignore")
    patterns = {
        line.strip()
        for line in open(gitignore, encoding="utf-8")
        if line.strip() and not line.strip().startswith("#")
    }
    assert ".env" in patterns


def test_module_exposes_a_single_source_of_record_path():

    import app.config as cfg

    files = resolve_env_files(cfg._backend_dir)
    expected = files[0] if files else os.path.join(cfg._backend_dir, ".env")
    assert cfg._env_path == expected
    assert os.path.isabs(cfg._env_path)
