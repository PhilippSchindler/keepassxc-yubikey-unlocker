# KeePassXC YubiKey Unlocker

An opinionated, personal CLI tool for protecting KeePassXC databases with a combination of a passphrase and a YubiKey.

## Overview

KeePassXC YubiKey Unlocker is designed to enhance the security of your KeePassXC database by requiring both something you know (a passphrase) and something you have (a YubiKey). The tool interacts directly with the YubiKey’s PIV interface to perform challenge–response authentication, derive cryptographic keys, and manage secure storage of (part of) the decryption key on the device. It also provides functionality for configuring YubiKeys, recovering master keys, unlocking databases, and even wiping the device’s PIV interface for a factory reset.

KeePassXC YubiKey Unlocker derives a master secret key to unlock a KeePassXC database from a passphrase and a YubiKey. So before using the tool you need to

-   configure your YubiKey,
-   create a KeePassXC database (setting the correct master secret key as password),
-   [modifying the KeePassXC YubiKey Unlocker configuration to your needs].

The next sections guide your through this process.

### YubiKey configuration

Before being able to unlock KeePassXC databases with this tool, the YubiKey(s) and database to be unlocked need to be setup appropriately.

Configuration of the YubiKey(s) can be accomplished using the provided configuration wizard.
Execute the following command to invoke it and follows the instructions:

```base
kyu configure
```

The configuration wizard allows you to configure multiple YubiKeys (to unlock the same database).
We highly advise setting up at least 2 YubiKeys: a primary YubiKey and a backup YubiKey and/or keep a backup of your master password in a secure place.

### KeePassXC database

In order to use the `kyu unlock` command to unlock and open your KeePassXC database, you need to set the password for the database to the master secret key derived and displayed during the YubiKey configuration process.

-   If you already have a KeePassXC database, choose "Database" ⇒ "Database Security" ⇒ "Change Password" to update the password to the derived master secret key.
-   Otherwise, create a fresh KeePassXC database and set the master secret key as password directly.

By default, `kyu unlock` encodes the master secret key as (space-separated) 32-word phrase in Byteswords format. This behavior can be changed in the configuration file or via a command line option.

**Currently supported formats:**

-   `bytewords` A 32 word phrase in [Bytewords format](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md). (Default)
-   `bip39` A 24 word phrase in [BIP39 format](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
-   `hex` A 256-bit key encoded as lowercase hexadecimal string.

Place your database file at `~/.kyu/default.kdbx`, or set a custom database path using the configuration file or via a command line parameter.

## Configuration

By default KeePassXC YubiKey Unlocker looks for a configuration file at `~/.kyu/config.toml`.
This configuration file can be used to specify

-   which database should be unlocked, and
-   in which format the key should be provided to KeePassXC.

Different database paths might be set depending on the inserted YubiKey.

**Default configuration**  
If no configuration file was detected, the following configuration is used when attempting to unlock a database.

```toml
[default]
path = "~/.kyu/default.kdbx"
format = "bytewords"
```

**Settings depending on the inserted YubiKey**  
Setting a custom database path, depending on which YubiKey is inserted can be accomplished by adding a configuration
section for each YubiKey's serial number. The values from these section take precedence over the defaults.

```toml
[1234567]  # Serial number of the YubiKey for the above database.
path = "~/path/to/database.kdbx"
format = "hex"  # Optional, overrides the default Bytewords format.

[9876543]
path = "~/path/to/another/database.kdbx"
format = "bip39"  # Optional, overrides the default Bytewords format.
```

## Command reference

```
Usage: kyu [OPTIONS] COMMAND [ARGS]...

  KeePassXC YubiKey Unlocker: An opinionated, personal CLI tool for protecting
  KeePassXC databases with a YubiKey.

  Under the hood, KeePassXC YubiKey Unlocker makes use of the YubiKey's PIV
  interface. It requires exclusive use of that interface and does interfere
  with other applications using the PIV interface. Other YubiKey applications
  (FIDO2, OpenPGP, ...) are not used. Thus, a single YubiKey may be safely
  shared between KeePassXC YubiKey Unlocker and those applications.

Options:
  --help  Show this message and exit.

Commands:
  configure  Configure YubiKeys for the use with this tool.
  recover    Recover master key from passphrase and YubiKey.
  unlock     Unlocks a KeePassXC database using a passphrase and a YubiKey.
  version    Display version information of this tool.
  wipe       Perform factory reset of a YubiKey's PIV interface.
```

## Cryptography

The security in KeePassXC YubiKey Unlocker is achieved by combining user-supplied data (passphrase) and hardware-backed secrets on the YubiKey. If a valid passphrase is entered, and a YubiKey is connected and touched when prompted, a master secret key is derived in a multiple steps. This master key is then encoded in the selected format (a Bytewords phrase by default), and used to unlock the KeePassXC database.

### Derivation of the master secret key

First, given the user's password, SHA3-256 is used to deterministically derive

-   a challenge (256 bits), and
-   a PIN code (56 bits).

Then, the challenge is sent to the YubiKey to be deterministically signed by the PIV interface of the connected YubiKey. Access to the underlying signing key is protected by the PIN code. The signing key never leaves the YubiKey. Access to it will be lost when an invalid passphrase (from which the PIN is received) is entered a number of times (default: 8 unlock attempts).

Finally, the response obtained from the above challenge/response protocol is combined with a static (also PIN protected) secret stored on YubiKey to derive the master secret key. This step is added to support unlocking the same KeePassXC database with different YubiKey (e.g., a primary YubiKey and one used as backup).

## Contributing

Contributions are welcome! To contribute:

1. Fork and create a feature branch from `main`.
2. Make your changes (and add tests).
3. Submit a pull request with a clear description.

For major changes, feel free to reach out or open an issue.

## License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for the full text.

This project is not affiliated with, endorsed by, or supported by Yubico or KeePassXC.
