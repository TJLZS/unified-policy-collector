# -*- coding: utf-8 -*-
"""ACL 策略（文件 ACL / 命名空间 / Seccomp / Capability）：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_acl_paths_config() -> StrategyPathsConfig:
    """ACL 采集涉及的关键目录（聚合用，单模块输出请用 get_acl_*_paths_config）。"""
    return build_paths_config(config_paths=[], log_paths=[])


def _acl_filesystem_commands():
    """文件 ACL（FileACL）模块命令。"""
    return {
        "getfacl_etc": "getfacl -pR /etc",
        "getfacl_usr_bin": "getfacl -pR /usr/bin",
        "getfacl_usr_sbin": "getfacl -pR /usr/sbin",
        "getfacl_var_log": "getfacl -pR /var/log",
        "filesystem_mounts": "mount | grep -E 'type ext|type xfs|type btrfs'",
        "suid_sgid_files": "find / -type f -perm /6000 -ls 2>/dev/null",
        "nouser_files": "find / -nouser -o -nogroup 2>/dev/null",
    }


def _acl_namespace_commands():
    """命名空间（Namespace）模块命令。"""
    return {
        "lsns": "lsns",
        "max_user_namespaces": "cat /proc/sys/user/max_user_namespaces",
        "pid_ns_inodes": "find /proc -maxdepth 1 -name '[0-9]*' -exec bash -c 'echo -n \"$1 \"; readlink -f \"$1\"/ns/user \"$1\"/ns/pid \"$1\"/ns/net \"$1\"/ns/mnt 2>/dev/null' _ {} \\; 2>/dev/null",
        "proc_self_cap": "grep -H Cap /proc/self/status",
        "cap_last_cap": "cat /proc/sys/kernel/cap_last_cap",
        "mount_propagation": "findmnt -o TARGET,PROPAGATION",
        "netns_list": "ip netns list",
        "proc_self_cgroup": "cat /proc/self/cgroup",
        "proc_cgroups": "cat /proc/cgroups",
        "uid_mapping": "cat /proc/self/uid_map",
        "gid_mapping": "cat /proc/self/gid_map",
    }


def _acl_seccomp_commands():
    """Seccomp 模块命令。"""
    return {
        "system_seccomp": "grep -r seccomp /etc/ 2>/dev/null",
        "process_seccomp": "ps -e -o pid,comm,args 2>/dev/null | grep -i seccomp || true",
        "docker_seccomp": "docker info --format '{{.SecurityOptions}}' 2>/dev/null || true",
        "docker_seccomp_profiles": "find /var/lib/docker -name 'seccomp.json' 2>/dev/null || true",
        "host_seccomp": "cat /boot/config-$(uname -r) 2>/dev/null | grep CONFIG_SECCOMP",
        "proc_self_seccomp": "awk '/^Seccomp:/ {print $2}' /proc/self/status",
        "all_pid_seccomp_summary": "grep -E 'Seccomp|filter_count' /proc/*/status 2>/dev/null || true",
        "systemd_syscall_filter": "grep -RHr SystemCallFilter /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null",
    }


def _acl_capability_commands():
    """Capability 模块命令。"""
    return {
        "file_capabilities": "getcap -r / 2>/dev/null || true",
        "boot_cap_config": "grep CONFIG_SECURITY /boot/config-$(uname -r) 2>/dev/null | grep -E 'CAP|SECURITY' || true",
        "proc_self_caps": "grep -E '^Cap(Prm|Eff|Bnd|Inh):' /proc/self/status",
        "cap_last_cap": "cat /proc/sys/kernel/cap_last_cap",
    }


def get_acl_file_acl_paths_config() -> StrategyPathsConfig:
    """FileACL 模块路径（不复制大目录，仅通过命令采集）。"""
    return build_paths_config(config_paths=[], log_paths=[])


def get_acl_file_acl_commands_config() -> StrategyCommandsConfig:
    """FileACL 模块命令。"""
    cmds = _acl_filesystem_commands()
    return build_commands_config(commands=cmds, status_group=cmds, log_group=None)


def get_acl_namespace_paths_config() -> StrategyPathsConfig:
    """Namespace 模块路径。"""
    return build_paths_config(config_paths=[], log_paths=[])


def get_acl_namespace_commands_config() -> StrategyCommandsConfig:
    """Namespace 模块命令。"""
    cmds = _acl_namespace_commands()
    return build_commands_config(commands=cmds, status_group=cmds, log_group=None)


def get_acl_seccomp_paths_config() -> StrategyPathsConfig:
    """Seccomp 模块路径。"""
    return build_paths_config(config_paths=[], log_paths=[])


def get_acl_seccomp_commands_config() -> StrategyCommandsConfig:
    """Seccomp 模块命令。"""
    cmds = _acl_seccomp_commands()
    return build_commands_config(commands=cmds, status_group=cmds, log_group=None)


def get_acl_capability_paths_config() -> StrategyPathsConfig:
    """Capability 模块路径。"""
    return build_paths_config(config_paths=[], log_paths=[])


def get_acl_capability_commands_config() -> StrategyCommandsConfig:
    """Capability 模块命令。"""
    cmds = _acl_capability_commands()
    return build_commands_config(commands=cmds, status_group=cmds, log_group=None)


def get_acl_commands_config() -> StrategyCommandsConfig:
    """ACL 聚合命令（四模块合并），与 ACL策略收集脚本.py 对齐。单模块输出请用 get_acl_*_commands_config。"""
    filesystem_commands = _acl_filesystem_commands()
    namespace_commands = _acl_namespace_commands()
    seccomp_commands = _acl_seccomp_commands()
    capability_commands = _acl_capability_commands()
    all_commands = {
        **filesystem_commands,
        **namespace_commands,
        **seccomp_commands,
        **capability_commands,
    }
    return build_commands_config(
        commands=all_commands,
        status_group=all_commands,
        log_group=None,
        extra_groups={
            "filesystem": filesystem_commands,
            "namespace": namespace_commands,
            "seccomp": seccomp_commands,
            "capability": capability_commands,
        },
    )
