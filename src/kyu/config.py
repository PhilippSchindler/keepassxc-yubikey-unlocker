from __future__ import annotations

import pathlib
import tomllib

from typing import Mapping, NamedTuple

from .types import KeyFormat


CONFIG_DIRECTORY = pathlib.Path("~/.kyu").expanduser()
CONFIG_PATH = CONFIG_DIRECTORY / "config.toml"

DEFAULT_DATABASE_PATH = CONFIG_DIRECTORY / "config.toml"
DEFAULT_KEY_FORMAT: KeyFormat = "bytewords"


class PerYubiKeyConfig(NamedTuple):
    database_path: pathlib.Path
    key_format: KeyFormat


class Config(NamedTuple):
    database_path: pathlib.Path
    key_format: KeyFormat
    per_yubikey_config: Mapping[int, PerYubiKeyConfig]

    def get_database_path(self, serial: int) -> pathlib.Path:
        if t := self.per_yubikey_config.get(serial):
            return t.database_path
        return self.database_path

    def get_key_format(self, serial: int) -> KeyFormat:
        if t := self.per_yubikey_config.get(serial):
            return t.key_format
        return self.key_format


def load(path: pathlib.Path = CONFIG_PATH) -> Config:
    """Load the configuration from the given configuration file."""
    with open(path, "rb") as f:
        database_path = DEFAULT_DATABASE_PATH
        key_format = DEFAULT_KEY_FORMAT
        per_yubikey_config: dict[int, PerYubiKeyConfig] = {}

        for key, value in tomllib.load(f).items():
            if key == "default" or key.isnumeric():
                if not isinstance(value, dict):
                    raise ValueError("Error in configuration file near [{key}].")

                y_path = DEFAULT_DATABASE_PATH
                y_format = DEFAULT_KEY_FORMAT
                for subkey, value in value.items():
                    if subkey == "path":
                        y_path = pathlib.Path(value).expanduser()
                    elif subkey == "format":
                        if value not in KeyFormat.__args__:
                            raise ValueError(f"Invalid key format {value!r}.")
                        y_format = value
                    else:
                        raise ValueError(f"Invalid configuration key {subkey!r}.")

                if key == "default":
                    database_path = y_path
                    key_format = y_format
                else:
                    per_yubikey_config[int(key)] = PerYubiKeyConfig(y_path, y_format)

            else:
                raise ValueError(f"Invalid configuration key {key!r}.")

        return Config(database_path, key_format, per_yubikey_config)


DEFAULT_CONFIG = Config(DEFAULT_DATABASE_PATH, DEFAULT_KEY_FORMAT, {})
