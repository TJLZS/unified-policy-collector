from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="统一安全策略采集Web控制台")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=8080, help="监听端口")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="显式允许监听非本机地址；请自行配置HTTPS和访问控制",
    )
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"} and not args.allow_remote:
        parser.error("监听非本机地址必须同时使用--allow-remote")

    import uvicorn

    print(f"Web控制台：http://{args.host}:{args.port}")
    uvicorn.run(
        "policy_collector.webapp:app",
        host=args.host,
        port=args.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()
