import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str


def run_command(command: list[str]) -> CommandResult:
    """
    Execute a predefined operating-system command safely.

    Arguments are passed as a list rather than through a shell.
    """
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )

    return CommandResult(
        command=command,
        return_code=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )
