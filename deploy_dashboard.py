from __future__ import annotations

import argparse
import os
import posixpath
from pathlib import Path

import paramiko


PROJECT_ROOT = Path(__file__).resolve().parent
RUNTIME_FILES = [
    "run_traffic_api_stdlib.py",
    "Bot种类划分.xlsx",
    "bot_summary.csv",
    "web/dashboard.html",
    "traffic_analytics/__init__.py",
    "traffic_analytics/api.py",
    "traffic_analytics/bot_taxonomy.py",
    "traffic_analytics/classification.py",
    "traffic_analytics/dashboard.py",
    "traffic_analytics/index_filtering.py",
    "traffic_analytics/ingest.py",
    "traffic_analytics/remote_source.py",
    "traffic_analytics/service.py",
    "traffic_analytics/settings.py",
    "traffic_analytics/storage.py",
    "traffic_analytics/support.py",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upload and restart the dashboard service.")
    parser.add_argument("--host", required=True, help="Remote SSH host, for example your-server-host")
    parser.add_argument("--user", required=True, help="Remote SSH user")
    parser.add_argument("--password", required=True, help="Remote SSH password")
    parser.add_argument("--remote-dir", default="/root/moseeker_bside_api", help="Remote deploy directory")
    parser.add_argument("--service", default="moseeker-bside-api.service", help="Remote systemd service name")
    parser.add_argument("--port", type=int, default=8013, help="Health check port")
    parser.add_argument("--health-retries", type=int, default=8, help="Health check retries after restart")
    parser.add_argument("--health-interval", type=int, default=3, help="Seconds between health retries")
    parser.add_argument("--skip-restart", action="store_true", help="Upload only, do not restart the service")
    return parser.parse_args()


def upload_runtime_files(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    for rel_path in RUNTIME_FILES:
        local_path = PROJECT_ROOT / Path(rel_path)
        if not local_path.exists():
            print(f"[SKIP] {rel_path} (missing locally)")
            continue
        remote_path = posixpath.join(remote_dir, *Path(rel_path).parts)
        remote_parent = posixpath.dirname(remote_path)
        ensure_remote_dir(sftp, remote_parent)
        sftp.put(str(local_path), remote_path)
        print(f"[UPLOAD] {rel_path}")


def ensure_remote_dir(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    parts = []
    current = remote_dir
    while current and current not in {"/", "."}:
        parts.append(current)
        current = posixpath.dirname(current)
    for item in reversed(parts):
        try:
            sftp.stat(item)
        except FileNotFoundError:
            sftp.mkdir(item)


def run_remote(client: paramiko.SSHClient, command: str, timeout: int = 120) -> tuple[str, str, int]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    code = stdout.channel.recv_exit_status()
    return out, err, code


def main() -> None:
    args = parse_args()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=args.host,
        username=args.user,
        password=args.password,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )
    try:
        sftp = client.open_sftp()
        try:
            upload_runtime_files(sftp, args.remote_dir)
        finally:
            sftp.close()

        compile_cmd = (
            f"cd {args.remote_dir} && "
            "/usr/bin/python3 -m compileall "
            "traffic_analytics run_traffic_api_stdlib.py"
        )
        out, err, code = run_remote(client, compile_cmd, timeout=300)
        print(out, end="")
        if err.strip():
            print(err, end="")
        if code != 0:
            raise RuntimeError(f"remote compile failed with exit code {code}")

        if not args.skip_restart:
            restart_cmd = f"systemctl restart {args.service}"
            out, err, code = run_remote(client, restart_cmd, timeout=120)
            print(out, end="")
            if err.strip():
                print(err, end="")
            if code != 0:
                raise RuntimeError(f"service restart failed with exit code {code}")

            health_ok = False
            for attempt in range(1, max(args.health_retries, 1) + 1):
                health_cmd = (
                    f"python3 - <<'PY'\n"
                    "import urllib.request\n"
                    f"print(urllib.request.urlopen('http://127.0.0.1:{args.port}/health', timeout=15).read().decode())\n"
                    "PY"
                )
                out, err, code = run_remote(client, health_cmd, timeout=30)
                if code == 0:
                    print(out, end="")
                    health_ok = True
                    break
                print(f"[HEALTH] attempt={attempt} failed")
                if err.strip():
                    print(err, end="")
                if attempt < max(args.health_retries, 1):
                    sleep_cmd = f"python3 - <<'PY'\nimport time\ntime.sleep({max(args.health_interval, 1)})\nPY"
                    run_remote(client, sleep_cmd, timeout=max(args.health_interval, 1) + 10)
            if not health_ok:
                raise RuntimeError("health check failed after retries")
    finally:
        client.close()


if __name__ == "__main__":
    main()
