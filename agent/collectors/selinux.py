from agent.command_runner import run_command


def collect_selinux_mode() -> str:
    result = run_command(["getenforce"])

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine SELinux mode: {result.stderr}"
        )

    return result.stdout
