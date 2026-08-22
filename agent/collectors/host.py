from agent.command_runner import run_command


def collect_hostname() -> str:
    result = run_command(["hostname"])

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine hostname: {result.stderr}"
        )

    return result.stdout


def collect_ip_addresses() -> list[str]:
    result = run_command(
        ["ip", "-br", "-4", "addr"]
    )

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine IP addresses: {result.stderr}"
        )

    addresses: list[str] = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 3:
            continue

        for value in fields[2:]:
            if "/" in value:
                addresses.append(value)

    return addresses
