import pytest


def pytest_ignore_collect(collection_path, config):
    del config
    return collection_path.name == "__pycache__"
