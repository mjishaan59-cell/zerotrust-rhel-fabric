from agent.command_runner import run_command


def collect_firewall_state() -> str:
    result = run_command(
        ["firewall-cmd", "--state"]
    )

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine firewall state: {result.stderr}"
        )

    return result.stdout
