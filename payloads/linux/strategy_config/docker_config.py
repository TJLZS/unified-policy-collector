# -*- coding: utf-8 -*-
"""Docker 策略：路径与命令的集中配置。"""

import os
from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_docker_paths_config() -> StrategyPathsConfig:
    """Docker 策略相关文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/docker/daemon.json",
            "/etc/default/docker",
            "/etc/sysconfig/docker",
            "/etc/systemd/system/docker.service",
            "/etc/systemd/system/docker.service.d/",
            os.path.expanduser("~/.docker/config.json"),
            "/root/.docker/config.json",
            "/etc/containerd/config.toml",
            "/etc/crio/crio.conf",
            "/etc/docker/registry/config.yml",
            "/etc/firewalld/services/docker-registry.xml",
            "/etc/firewalld/services/docker-swarm.xml",
            "/etc/apparmor.d/docker",
            "/etc/apparmor.d/docker-default",
            "/etc/apparmor.d/abstractions/docker",
            "/etc/selinux/targeted/contexts/files/file_contexts.local",
            "/etc/selinux/targeted/modules/active/modules/docker.pp",
            "/etc/rsyslog.d/docker.conf",
            "/etc/docker/certs.d/",
            "/etc/docker/tls/",
            "/etc/subuid",
            "/etc/subgid",
        ],
        log_paths=[],
    )


def get_docker_commands_config() -> StrategyCommandsConfig:
    """Docker 安全状态与配置采集命令。"""
    all_commands = {
        "docker_version": "docker --version 2>&1",
        "docker_version_detailed": "docker version 2>&1",
        "dockerd_version": "dockerd --version 2>&1",
        "docker_info": "docker info 2>&1",
        "docker_system_info": "docker system info 2>&1",
        "service_status": "systemctl status docker 2>/dev/null",
        "service_enabled": "systemctl is-enabled docker 2>/dev/null",
        "running_processes": "ps aux | grep -E '(docker|dockerd|containerd)' | grep -v grep",
        "docker_images": "docker images 2>&1",
        "docker_images_detailed": "docker images --format '{{.Repository}}:{{.Tag}}' 2>&1",
        "docker_ps": "docker ps -a 2>&1",
        "docker_ps_format": "docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}' 2>&1",
        "docker_networks": "docker network ls 2>&1",
        "docker_volumes": "docker volume ls 2>&1",
        "docker_events_recent": "timeout 2 docker events --since 10m 2>&1 || echo 'No events or timeout'",
        "iptables_docker": "iptables -L -n | grep -i docker 2>&1",
        "apparmor_docker": "aa-status 2>/dev/null | grep docker || echo 'No AppArmor docker profiles'",
        "selinux_docker": "ls -Z /usr/bin/docker /var/lib/docker 2>&1",
    }
    status_group = dict(all_commands)
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
