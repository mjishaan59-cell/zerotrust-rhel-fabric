from agent.command_runner import run_command


def collect_listening_tcp_ports() -> list[int]:
    result = run_command(
        ["ss", "-lntH"]
    )

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine listening ports: {result.stderr}"
        )

    ports: set[int] = set()

    for line in result.stdout.splitlines():
        fields = line.split()

        if len(fields) < 4:
            continue

        local_address = fields[3]

        if ":" not in local_address:
            continue

        port_text = local_address.rsplit(":", 1)[-1]

        if port_text.isdigit():
            ports.add(int(port_text))

    return sorted(ports)
