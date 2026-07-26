# -*- coding: utf-8 -*-
"""LUKS 策略：路径与命令的集中配置。"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_luks_paths_config() -> StrategyPathsConfig:
    """LUKS 相关配置文件/目录路径。"""
    return build_paths_config(
        config_paths=[
            "/etc/crypttab",
            "/etc/fstab",
            "/etc/mtab",
            "/etc/default/grub",
            "/boot/grub/grub.cfg",
            "/etc/cryptsetup-initramfs/",
            "/etc/lvm/",
            "/etc/fstab.d/",
            "/etc/systemd/system/cryptsetup.target.wants/",
            "/usr/share/cryptsetup/",
            "/run/cryptsetup/",
        ],
        log_paths=[],
    )


def get_luks_commands_config() -> StrategyCommandsConfig:
    """LUKS 状态与设备采集命令。"""
    all_commands = {
        "version": "cryptsetup --version",
        "status": "systemctl status cryptsetup 2>/dev/null",
        "enabled": "systemctl is-enabled cryptsetup 2>/dev/null",
        "list_devices": "blkid | grep TYPE=*crypto_LUKS*",
        "lsblk_crypto": "lsblk -f | grep -E '(LUKS|crypt)'",
        "dmsetup_status": "dmsetup status -c",
        "dmsetup_ls": "dmsetup ls --target crypt",
        "proc_partitions": "cat /proc/partitions",
        "block_devices": "ls -la /sys/block/",
        "disk_usages": "df -h",
        "mount_info": "mount | grep /dev/mapper",
        "crypttab": "cat /etc/crypttab 2>/dev/null",
        "fstab": "cat /etc/fstab 2>/dev/null",
        "mtab": "cat /etc/mtab 2>/dev/null",
        "grub_config": "cat /etc/default/grub 2>/dev/null",
        "boot_entries": "ls -la /boot/grub/ 2>/dev/null",
        "grub_menu": "grep -E '(crypt|luks)' /boot/grub/grub.cfg 2>/dev/null | head -20",
        "syslog_luks": "grep -iE '(luks|crypt|cryptsetup)' /var/log/syslog 2>/dev/null | tail -20",
        "messages_luks": "grep -iE '(luks|crypt|cryptsetup)' /var/log/messages 2>/dev/null | tail -20",
        "boot_log": "journalctl -u cryptsetup 2>/dev/null | tail -30",
        "crypto_modules": "lsmod | grep -E '(aes|crypto|dm_crypt|cryptd)'",
        "dm_modules": "lsmod | grep dm",
        "running_processes": "ps aux | grep -E '(cryptsetup|luks)'",
        "kernel_crypto": "cat /proc/crypto 2>/dev/null | head -30",
    }
    status_group = {
        "luks_version": all_commands["version"],
        "luks_status": all_commands["status"],
        "luks_enabled": all_commands["enabled"],
        **{k: v for k, v in all_commands.items() if k not in ("version", "status", "enabled")},
    }
    return build_commands_config(
        commands=all_commands,
        status_group=status_group,
        log_group=None,
    )
