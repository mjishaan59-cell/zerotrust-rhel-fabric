# ZeroTrust RHEL Cloud Fabric

ZeroTrust RHEL Cloud Fabric (ZTRF) is a security-focused platform for
RHEL 10 workloads.

The platform evaluates workload access using identity, resource,
network context, and host security posture.

## Project Goals

- Zero Trust access decisions
- RHEL security posture monitoring
- Policy-based authorization
- Risk evaluation
- Security event detection
- Automated remediation
- Ansible integration
- Containerized deployment
- GitHub-based development
- Cloud deployment support

## Development Environment

- RHEL 10
- VMware Workstation Pro
- Git
- Ansible
- Python
- FastAPI
- PostgreSQL
- Podman / Docker
- AWS or Azure for cloud deployment

## Architecture

The system will contain a central controller and security agents
running on protected RHEL workloads.
