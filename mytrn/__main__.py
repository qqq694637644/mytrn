"""mytrn CLI: init once, configure through local Web UI, run A/B agents."""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .agent import Agent
from .config import initialize, load_json


async def run_agent(role: str, config_path: Path):
    configuration = load_json(config_path)
    agent = Agent(role, config_path, configuration)
    try:
        await agent.start()
        print(f"mytrn {role.upper()} ready | Web UI: http://{configuration['web_bind']}:{configuration['web_port']}", flush=True)
        print("Use the admin_token printed by 'python -m mytrn init' to open the Web UI.", flush=True)
        while True:
            await asyncio.sleep(3600)
    finally:
        await agent.stop()


def main():
    parser = argparse.ArgumentParser(description="mytrn: B actively connects A through WARP SOCKS5 UDP")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("a", "b"):
        p = sub.add_parser(name, help=f"run {name.upper()} agent")
        p.add_argument("--config", default=f"config.{name}.json")
        p.add_argument("--debug", action="store_true")
    initial = sub.add_parser("init", help="generate local config with strong random tokens")
    initial.add_argument("role", choices=("a", "b"))
    initial.add_argument("--config", default=None)
    args = parser.parse_args()

    if args.command == "init":
        path = Path(args.config or f"config.{args.role}.json")
        try:
            config = initialize(path, args.role)
        except FileExistsError as exc:
            print(exc, file=sys.stderr)
            return 2
        print(f"Created {path}. Keep it private; never commit it.")
        print(f"Web UI admin_token: {config['admin_token']}")
        print("Copy A's control_token and data_psk into B's config using the Web UI.")
        return 0

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        asyncio.run(run_agent(args.command, Path(args.config)))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"mytrn failed to start: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
