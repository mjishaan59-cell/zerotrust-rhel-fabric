from agent.command_runner import run_command


def test_command_runner_success():
    result = run_command(["printf", "hello"])

    assert result.return_code == 0
    assert result.stdout == "hello"


def test_command_runner_failure():
    result = run_command(["sh", "-c", "exit 7"])

    assert result.return_code == 7
