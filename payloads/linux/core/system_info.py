# -*- coding: utf-8 -*-
"""系统类型检测（发行版识别），供断点与报告使用。"""

from __future__ import annotations

import os
from typing import Optional


def detect_system_type() -> str:
    """检测当前系统类型（debian/redhat/centos/arch/ubuntu 等）。"""
    try:
        if os.path.exists("/etc/debian_version"):
            return "debian"
        if os.path.exists("/etc/redhat-release"):
            return "redhat"
        if os.path.exists("/etc/centos-release"):
            return "centos"
        if os.path.exists("/etc/arch-release"):
            return "arch"
        if os.path.exists("/etc/slackware-version"):
            return "slackware"
        if os.path.exists("/etc/SuSE-release"):
            return "suse"
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as f:
                content = f.read().lower()
                if "ubuntu" in content:
                    return "ubuntu"
                if "kali" in content:
                    return "kali"
                if "debian" in content:
                    return "debian"
                if "centos" in content or "rhel" in content or "redhat" in content:
                    return "redhat"
        return "unknown"
    except Exception:
        return "unknown"
