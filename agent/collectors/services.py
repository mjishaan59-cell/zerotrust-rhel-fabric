from agent.command_runner import run_command


def collect_running_services() -> list[str]:
    result = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-legend",
            "--no-pager",
        ]
    )

    if result.return_code != 0:
        raise RuntimeError(
            f"Unable to determine running services: {result.stderr}"
        )

    services: list[str] = []

    for line in result.stdout.splitlines():
        fields = line.split()

        if fields:
            services.append(fields[0])

    return sorted(set(services))
