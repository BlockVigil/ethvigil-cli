import pytest
from click_cli import cli

def test_help(isolated_cli_runner):
    result = isolated_cli_runner.invoke(cli, ['--help'])
    assert result.exception == None
