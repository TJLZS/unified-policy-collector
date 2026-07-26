class CollectorError(RuntimeError):
    """可向CLI安全展示的采集错误。"""


class TransportError(CollectorError):
    """连接、认证、命令或文件传输失败。"""
