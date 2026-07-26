# -*- coding: utf-8 -*-
"""
K8S/Kind 集群策略：路径与命令的集中配置。

配置文件来自容器内路径（通过 docker cp 采集），此处仅配置 kubectl 命令。
"""

from .paths_commands import (
    StrategyPathsConfig,
    StrategyCommandsConfig,
    build_paths_config,
    build_commands_config,
)


def get_k8s_paths_config() -> StrategyPathsConfig:
    """K8S 策略相关路径（宿主机上无对应路径，配置文件在容器内）。"""
    return build_paths_config(
        config_paths=[],
        log_paths=[],
        extra_paths=[
            ("/etc/kubernetes/manifests/kube-apiserver.yaml", "容器内 API Server 配置"),
            ("/etc/kubernetes/manifests/kube-controller-manager.yaml", "容器内控制器配置"),
            ("/etc/kubernetes/manifests/kube-scheduler.yaml", "容器内调度器配置"),
            ("/etc/kubernetes/manifests/etcd.yaml", "容器内 etcd 配置"),
            ("/var/log/kubernetes/kube-apiserver.log", "容器内 API Server 日志"),
        ],
    )


def get_k8s_commands_config() -> StrategyCommandsConfig:
    """K8S 集群状态与安全资源采集命令（kubectl）。"""
    status_commands = {
        "version": "kubectl version --output=yaml",
        "cluster_info": "kubectl cluster-info",
        "api_health": "kubectl get --raw '/healthz'",
        "nodes": "kubectl get nodes -o wide",
        "namespace_labels": "kubectl get namespaces --show-labels",
        "node_describe": "kubectl describe node hjb996-control-plane",
        "events": "kubectl get events --all-namespaces --sort-by='.lastTimestamp'",
        "all_resources": "kubectl get all --all-namespaces",
    }
    resource_commands = {
        "network_policies": "kubectl get networkpolicies --all-namespaces -o yaml",
        "roles": "kubectl get roles --all-namespaces -o yaml",
        "cluster_roles": "kubectl get clusterroles -o yaml",
        "role_bindings": "kubectl get rolebindings --all-namespaces -o yaml",
        "cluster_role_bindings": "kubectl get clusterrolebindings -o yaml",
        "pods_sample": "kubectl get pods --all-namespaces -o yaml | head -1000",
        "validating_webhooks": "kubectl get validatingwebhookconfigurations -o yaml",
        "mutating_webhooks": "kubectl get mutatingwebhookconfigurations -o yaml",
    }
    all_commands = {**status_commands, **resource_commands}
    return build_commands_config(
        commands=all_commands,
        status_group=status_commands,
        log_group=None,
        extra_groups={"k8s_resources": resource_commands},
    )
