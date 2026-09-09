"""Docker integration is an explicit opt-in; unit and host tests remain the default."""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--docker",
        action="store_true",
        help="Include real Docker integration tests (requires Docker and host ptrace privileges)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: requires a real Docker daemon and host ptrace privileges")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if getattr(item.cls, "docker_integration", False):
            item.add_marker(pytest.mark.docker)
    if config.getoption("--docker"):
        return
    selected, deselected = [], []
    for item in items:
        (deselected if item.get_closest_marker("docker") else selected).append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)
