"""
Module for integration with KeePassXC, i.e., for starting KeePassXC and opening a database to be unlocked.
"""

import pathlib
import subprocess

from .config import CONFIG_DIRECTORY

DEFAULT_CONFIG_PATH = CONFIG_DIRECTORY / "keepassxc.ini"


def open_database(
    unlock_phrase: str,
    database_path: pathlib.Path,
    config_path: pathlib.Path | None = DEFAULT_CONFIG_PATH,
) -> None:
    """Calls KeePassXC to open all given databases."""
    # This assumes a globally available installation of KeePassXC.
    # For flatpak version an invocation via `flatpak run org.keepassxc.KeePassXC` is possible.
    subprocess_args = ["keepassxc", "--pw-stdin"]
    if config_path and config_path.is_file():
        subprocess_args.append("--config")
        subprocess_args.append(str(config_path))
    subprocess_args.append(str(database_path))

    p = subprocess.Popen(
        subprocess_args,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    assert p.stdin is not None
    p.stdin.write(unlock_phrase)
    p.stdin.close()
