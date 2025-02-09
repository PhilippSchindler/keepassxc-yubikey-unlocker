"""
Command line interface.
"""

import atexit
import functools
import getpass
import hashlib
import importlib.metadata
import itertools
import logging
import pathlib
import re
import readline
import secrets
import subprocess
import sys
import termios
import textwrap
import threading
import time

from typing import Callable, Concatenate, Literal, ParamSpec, TypeVar

from . import bip39, bytewords, config, crypto, keepassxc
from .types import KeyFormat
from .hardware import (
    YubiKey,
    YubiKeyError,
    NoYubiKeyDetectedError,
    MultipleYubiKeysDetectedError,
    InvalidPinError,
)

import click

logging.getLogger().setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)
logger.setLevel(logging.CRITICAL)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
logger.addHandler(handler)


LOGO = r"""
  _ __           ___              __  _ ___ 
 | / / ___  ___ | . \ ___  ___ ___\ \/ |  _>
 |  \ / ._>/ ._>|  _/<_> |<_-<<_-< \ \ | <__
 |_\_\\___.\___.|_|  <___|/__//__/_/\_\`___/

  _ _       _    _  _               _ _       _            _
 | | | _ _ | |_ <_>| |__ ___  _ _  | | |._ _ | | ___  ___ | |__ ___  _ _
 \   /| | || . \| || / // ._>| | | | ' || ' || |/ . \/ | '| / // ._>| '_>
  |_| `___||___/|_||_\_\\___.`_. | `___'|_|_||_|\___/\_|_.|_\_\\___.|_|
                             <___'
"""[
    1:
]


class TouchInteraction:

    def __init__(self, prompt_text: str, completion_text: str):
        self.prompt_text = prompt_text
        self.completion_text = completion_text

    def on_touched_requested(self) -> None:
        print(f"{self.prompt_text}... ")
        print()
        print("=====================================")
        print(">>> PLEASE TOUCH YOUR YUBIKEY NOW <<<")
        print("=====================================")
        print()

    def on_operation_completed(self) -> None:
        for _ in range(5):
            cursor_up()
            clear_line()
        cursor_up()
        set_cursor_horizontal(len(self.prompt_text) + 5)
        print(f"{self.completion_text}.")


P = ParamSpec("P")
R = TypeVar("R")


def with_single_connected_yubikey(func: Callable[Concatenate[YubiKey, P], R]) -> Callable[P, R]:
    """Waits for a YubiKey to be connected and then invokes the provided function with a reference to that YubiKey."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        waiting_message_printed = False
        dots = 0

        for i in itertools.count():
            try:
                with YubiKey.get_unique_connected_yubikey() as yubikey:
                    clear_line()
                    show_cursor()
                    print("YubiKey detected.")
                    return func(yubikey, *args, **kwargs)

            except NoYubiKeyDetectedError:
                if waiting_message_printed:
                    clear_line()

                print(f"Waiting for YubiKey to be inserted{'.'*dots} ", end="", flush=True)
                dots += 1
                dots %= 6
                time.sleep(0.25)
                waiting_message_printed = True

            except MultipleYubiKeysDetectedError:
                clear_line()
                error("Multiple YubiKeys detected.")
                print("Aborting.")
                exit(1)

            except YubiKeyError:
                i -= 1

        assert False, "not reachable"

    return wrapper


def encode_key(key: bytes, format: KeyFormat) -> str:
    match format:
        case "bytewords":
            return bytewords.encode(key)
        case "bip39":
            return bip39.encode(key)
        case "hex":
            return key.hex()
        case _:
            raise NotImplementedError


def decode_key(phrase: str, format: KeyFormat) -> bytes:
    match format:
        case "bytewords":
            return bytewords.decode(phrase)
        case "bip39":
            return bip39.decode(phrase)
        case "hex":
            return bytes.fromhex(phrase)
        case _:
            raise NotImplementedError


# Various escape codes are using the for implementing the CLI interface.
# See, for example, https://notes.burke.libbey.me/ansi-escape-codes/ for a guide.


def show_cursor() -> None:
    print("\x1b[?25h", end="", flush=True)


def hide_cursor() -> None:
    print("\x1b[?25l", end="", flush=True)


def clear_line() -> None:
    print("\x1b[2K\r", end="", flush=True)


def cursor_up() -> None:
    print("\x1b[1A", end="", flush=True)


def cursor_down() -> None:
    print("\x1b[1B", end="", flush=True)


def save_cursor() -> None:
    print("\x1b[s", end="", flush=True)


def restore_cursor() -> None:
    print("\x1b[u", end="", flush=True)


def set_cursor_horizontal(x: int) -> None:
    print(f"\x1b[{x}G", end="", flush=True)


def reset_line() -> None:
    reset_lines(1)


def reset_lines(num_lines: int) -> None:
    for _ in range(num_lines):
        cursor_up()
        clear_line()


def print_info_box(title: str, content: list[str], width: int = 80) -> None:
    """Returns a 'fancy-looking' box to highlight import information."""
    content_width = width - 6
    wrapped_content = [" " * content_width]
    for line in content:
        if len(line) <= content_width:
            wrapped_content.append(line.ljust(content_width))
        else:
            for wrapped_line in textwrap.wrap(line, content_width):
                wrapped_content.append(wrapped_line.ljust(content_width))
    wrapped_content.append(" " * content_width)

    box_lines = []
    box_lines.append("".join(["╭", "─" * (len(title) + 4), "╮"]).center(width))
    l1 = (width - len(title) - 8) // 2
    l2 = (width - len(title) - 8) - l1
    box_lines.append("".join(["╔", "═" * l1, f"╡  {title}  ╞", "═" * l2, "╗"]))
    box_lines.append("".join(["║", " " * l1, "╰", "─" * (len(title) + 4), "╯", " " * l2, "║"]))
    for line in wrapped_content:
        box_lines.append("".join(["║  ", line, "  ║"]))
    box_lines.append("".join(["╚", "═" * (width - 2), "╝"]))

    print()
    print("\n".join(box_lines))
    print()


def print_key_box(title: str, words: list[str], hex_value: str, fmt: KeyFormat) -> int:
    """Print a box to display a Bytewords or BIP39 key. Bytewords example:
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║ BYTEWORDS MASTER KEY {title}                                                 ║
    ╟──────────────────────────────────────────────────────────────────────────────╢
    ║ 1. paid    6. skew   11. cats   16. zone   21. back   26. easy   31. cash    ║
    ║ 2. liar    7. junk   12. dark   17. vows   22. peck   27. nail   32. jazz    ║
    ║ 3. deli    8. into   13. fuel   18. kite   23. undo   28. into               ║
    ║ 4. days    9. math   14. data   19. cusp   24. junk   29. many               ║
    ║ 5. judo   10. flap   15. song   20. yurt   25. judo   30. hang   {words}     ║
    ╟──────────────────────────────────────────────────────────────────────────────╢
    ║ a9b4103ea301ac79f7c62ca95255221ac49f08f0aa97c1813529e3ff9a894995 {hex_value} ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """
    if fmt == "hex":
        raise NotImplementedError

    # Width of the box to draw, includes the border characters.
    WIDTH = 80

    # Indent level, includes the border character.
    INDENT = 2

    # Maximum value for the spacing between two columns of words.
    MAX_COL_SPACING = 5

    # Box drawing characters.
    # TL, TR, BL, BR, H, V, SL, S, SR = "┏ ┓ ┗ ┛ ━ ┃ ┠ ─ ┨".split()
    TL, TR, BL, BR, H, V, SL, S, SR = "╔ ╗ ╚ ╝ ═ ║ ╟ ─ ╢".split()

    def write(row: int, col: int, value: str) -> None:
        for i, char in enumerate(value):
            rows[row][col + i] = char

    height = 6
    CONTENT_SIZE_TABLE: dict[tuple[str, int], tuple[int, int, int]] = {
        ("bip39", 12): (3, 5, 8),
        ("bip39", 15): (3, 5, 8),
        ("bip39", 18): (4, 5, 8),
        ("bip39", 21): (5, 5, 8),
        ("bip39", 24): (5, 5, 8),
        ("bytewords", 16): (3, 6, 4),
        ("bytewords", 20): (3, 7, 4),
        ("bytewords", 24): (4, 6, 4),
        ("bytewords", 28): (4, 7, 4),
        ("bytewords", 32): (5, 7, 4),
    }
    content_rows, content_cols, word_length = CONTENT_SIZE_TABLE[(fmt, len(words))]
    height += content_rows

    # Draw the borders of the box.
    rows = [[" "] * WIDTH for _ in range(height)]
    write(0, 0, TL + (H * (WIDTH - 2)) + TR)
    write(1, 0, V + (" " * (WIDTH - 2)) + V)
    write(2, 0, SL + (S * (WIDTH - 2)) + SR)
    for i in range(content_rows):
        write(3 + i, 0, V + (" " * (WIDTH - 2)) + V)
    if hex_value:
        write(-3, 0, SL + (S * (WIDTH - 2)) + SR)
        write(-2, 0, V + (" " * (WIDTH - 2)) + V)
    write(-1, 0, BL + (H * (WIDTH - 2)) + BR)

    # Draw the title in the top left.
    write(1, INDENT, title)

    # Draw the checksum (if enabled) in the bottom right.
    # write(-2, -(len(hex_value) + INDENT), hex_value)
    write(-2, 2, hex_value)

    # Draw the words neatly into a table format, include words indices for readability.
    cols_widths = [len(f"{(i + 1) * content_rows}. {'w'* word_length}") for i in range(content_cols)]
    required_width = sum(cols_widths)
    col_spacing = (WIDTH - (INDENT * 2 + required_width)) // (content_cols - 1)
    col_spacing = min(col_spacing, MAX_COL_SPACING)

    for i, word in enumerate(words):
        col = i % content_cols
        row = i // content_cols
        extra_indent = " " if len(str(i + 1)) == 1 else ""
        write(3 + row, INDENT + sum(cols_widths[:col]) + col * col_spacing, f"{extra_indent}{i+1}. {word}")

    # Join the contents of all rows and print them.
    print()
    print("\n".join("".join(char) for char in rows))
    print()
    return len(rows) + 2


def passphrase_prompt(text: str = "Enter passphrase: ", text_completed: str = "Passphrase entered.") -> str:
    """Prompts the user to enter a passphrase. The input is invisible."""
    passphrase = hidden_prompt(text)
    reset_line()
    print(text_completed)
    return passphrase


def checked_passphrase_prompt() -> str:
    for i in itertools.count():
        passprase = passphrase_prompt()
        repeat = passphrase_prompt("Repeat passphrase: ", "Passphrase repeated.")
        print()
        if passprase == repeat:
            print("Successfully checked passphrases for equality.")
            print()
            return passprase

        reset_lines(3 if i == 0 else 5)
        error("Passphrases do not match. Retry.")
        print()

    assert False, "not reachable"


def error(text: str) -> None:
    print("\x1b[31m" + f"ERROR: {text}" + "\x1b[0m")


def prompt(text: str) -> str:
    print()
    reset_line()
    return input(text).strip()


def hidden_prompt(text: str) -> str:
    print()
    reset_line()
    return getpass.getpass(text)


def prompt_with_prefill(text, prefilled_text):
    def hook():
        readline.insert_text(prefilled_text)
        readline.redisplay()

    print()
    reset_line()
    readline.set_pre_input_hook(hook)
    result = input(text).strip()
    readline.set_pre_input_hook()
    return result


def yes_no_prompt(question: str, default: Literal["Yes", "No"] | None = None) -> bool:
    """Displays a yes/no question with a prompt for user input."""
    for i in itertools.count():
        if default == "Yes":
            answer = print(f"{question} [YES/no] ")
        elif default == "No":
            answer = print(f"{question} [yes/NO] ")
        else:
            answer = print(f"{question} [yes/no] ")

        answer = prompt("Your response: ")

        answer = answer.strip() or default
        reset_lines(2 if i == 0 else 4)

        if answer is None:
            error("Input required, please try again.")
            print()
        elif answer.upper() in ("YES.", "YES", "Y"):
            print(question)
            print("Your response: Yes.")
            print()
            return True
        elif answer.upper() in ("NO.", "NO", "N"):
            print(question)
            print("Your response: No.")
            print()
            return False
        else:
            error("Invalid input, please try again.")
            print()

    assert False, "not reachable"


def choice_prompt(question: str, options: list[str]) -> int:
    """Displays a question where the user must select one of the given possible options."""
    assert len(options) >= 2

    print(question)
    for i, option in enumerate(options):
        print(f" {i + 1}. {option}")
    print()

    for i in itertools.count():
        if len(options) == 2:
            answer = prompt(f"Enter 1 or 2 to select: ")
        if len(options) == 3:
            answer = prompt(f"Enter 1, 2, or 3 to select: ")
        else:
            answer = prompt(f"Enter 1, 2, ..., or {len(options) + 1} to select: ")

        answer = answer.strip().replace(".", "")
        reset_lines(1 if i == 0 else 3)

        if answer == "":
            error("Selection required, please try again.")
            print()
            continue

        try:
            answer = int(answer) - 1
            if not (0 <= answer < len(options)):
                raise ValueError

            print(f"Your selection: {options[answer]}")
            print()
            return answer

        except ValueError:
            error("Invalid selection, please try again.")
            print()

    assert False, "not reachable"


def numeric_prompt(question: str, default: int, min: int, max: int) -> int:
    print(question)
    print(f"Allowed range: {min} to {max}; Default: 8")
    print()
    for i in itertools.count():
        answer = prompt("Your selection: ")

        reset_lines(1 if i == 0 else 3)
        try:
            value = int(answer or default)
            if min <= value <= max:
                print(f"Your selection: {value}")
                print()
                return value
            else:
                error(f"Provided value {value!r} out of range, please try again.")
                print()

        except ValueError:
            error("Invalid input, please try again.")
            print()

    assert False, "not reachable"


def word_prompt(prefilled_index: int, num_words: int, wordlist: dict[str, int]) -> tuple[int, str]:
    for i in itertools.count():
        answer = prompt_with_prefill("Enter index and word: ", f"{prefilled_index + 1}. ").lower()
        match = re.fullmatch(r"(\d+)\.?\s*([a-zA-z]+)", answer)
        if match is None:
            index, word = -1, ""
        else:
            index = int(match.group(1)) - 1
            word = match.group(2)

        reset_lines(1 if i == 0 else 3)
        if 0 <= index < num_words and word in wordlist:
            print(f"Enter index and word: {prefilled_index + 1}. {word}")
            return (index, word)
        elif answer == "" or re.fullmatch(r"\d+\.?", answer):
            error("No word entered, please try again.")
        elif 0 <= index <= num_words:
            error(f"Word '{word}' not in wordlist. Please try again.")
        elif word in wordlist:
            error(f"Word index '{index + 1}' out of range. Please try again.")
        else:
            error("Invalid input, please try again.")
        print()

    assert False, "not reachable"


def word_indices_prompt(num_words: int, clear_pref_error: bool = False) -> list[int]:
    pattern = r"none|all|(\b(" + "|".join(str(v) for v in range(1, num_words + 1)) + r")[\s,;]*\b)+"
    for i in itertools.count():
        print(f"Type the indices of the words to modify. [1/2/.../{num_words}/none/all]")
        answer = prompt("Your input: ").lower()

        if i > 0 or clear_pref_error:
            reset_lines(4)
        else:
            reset_lines(2)

        if re.fullmatch(pattern, answer):
            print("Type the indices of the words to modify.")
            if answer == "all":
                indices = list(range(num_words))
                print(f"Your response: All.")
            elif answer == "none":
                indices = []
                print(f"Your response: None.")
            else:
                indices = [int(v) - 1 for v in answer.replace(",", " ").split()]
                print(f"Your response: {', '.join(str(v + 1) for v in indices)}")
            return indices
        else:
            if answer == "":
                error(f"Input required, please try again.")
            else:
                error("Invalid input, please try again.")
            print()

    assert False, "not reachable"


def _master_key_phrase_prompt(
    fmt: Literal["bytewords", "bip39"],
    wordlist: dict[str, int],
    words: list[str],
) -> tuple[int, Literal["confirm", "clear", "word-entered"], tuple[int, str] | list[int] | None]:

    decode = bytewords.decode if fmt == "bytewords" else bip39.decode
    completed = all(w in wordlist for w in words)
    hex_value_for_display = "input incomplete"
    checksum_ok = True
    error_text = ""

    if completed:
        try:
            hex_value_for_display = decode(" ".join(words)).hex()
        except:
            hex_value_for_display = "input invalid, checksum verification failed"
            error_text = "Input completed but checksum verification failed."
            checksum_ok = False

    num_lines = print_key_box(f"{fmt.upper()} MASTER KEY", words, hex_value_for_display, fmt)

    if error_text:
        error(error_text)
        print()
        num_lines += 2

    if completed:
        if checksum_ok:
            if yes_no_prompt("Double-check the entered master key. Is it correct?"):
                return (0, "confirm", None)
            reset_lines(3)
            num_lines += 2

        return (
            num_lines,
            "clear",
            word_indices_prompt(len(words), not checksum_ok),
        )

    num_lines += 1
    prefilled_index = words.index("")
    return num_lines, "word-entered", word_prompt(prefilled_index, len(words), wordlist)


def master_key_phrase_prompt(fmt: Literal["bytewords", "bip39"]) -> str:
    print(
        "\n".join(
            textwrap.wrap(
                "Enter the master key to protect with the passphrase and YubiKey. The key is entered word by word. The "
                "word indices are prefilled in the prompt, but can be changed to modify a previously entered word.",
                80,
            )
        )
    )
    num_words, wordlist, decode_func = {
        "bytewords": (32, bytewords.WORD_INDICES, bytewords.decode),
        "bip39": (24, bip39.WORD_INDICES, bip39.decode),
    }[fmt]

    words: list[str] = [""] * num_words
    while True:
        num_lines, action, result = _master_key_phrase_prompt(fmt, wordlist, words)
        match action:
            case "confirm":
                return " ".join(words)

            case "clear":
                assert isinstance(result, list), "expected list of indices as result"
                indices: list[int] = result
                for i in indices:
                    words[i] = ""

            case "word-entered":
                assert isinstance(result, tuple)
                i, word = result
                words[i] = word

            case _:
                assert False, "case not handled"

        reset_lines(num_lines)


def master_key_prompt(format: KeyFormat | None, generate_key: bool | None) -> bytes:
    fmt: KeyFormat = (
        format
        or ["bytewords", "bip39", "hex"][
            choice_prompt(
                "Which master key format should be used?",
                ["Bytewords Phrase (32 words, recommended)", "BIP39 Phrases (24 words)", "Hex String (64 characters)"],
            )
        ]  # type: ignore
    )

    if generate_key is None:
        generate_key = yes_no_prompt("Generate and use a new random master key?", default="Yes")

    if generate_key:
        master_key = secrets.token_bytes(32)
        print("Generating master key... Done.")
        if fmt == "hex":
            print("Master key:", master_key.hex())
            print()
        else:
            words = {
                "bytewords": bytewords.encode(master_key),
                "bip39": bip39.encode(master_key),
            }[fmt].split()
            print_key_box(f"{fmt.upper()} MASTER KEY", words, master_key.hex(), fmt)
        return master_key

    if fmt in ("bytewords", "bip39"):
        return decode_key(master_key_phrase_prompt(fmt), fmt)

    if fmt != "hex":
        raise ValueError(f"Invalid format {fmt!r} specified.")

    for i in itertools.count():
        print("Enter 256 bit master key (as hex string) below.")
        answer = prompt("Master key: ")

        reset_lines(2 if i == 0 else 4)
        try:
            value = bytes.fromhex(answer)
            if len(value) == 32:
                print("Enter the master key to protect with the passphrase and YubiKey.")
                print(f"Master key: {value.hex()}")
                print()
                return value

            if value == b"":
                error(f"Input required, please try again.")
            else:
                error(f"256 bit key required, got {len(value) * 8} bit, please try again.")

        except ValueError:
            error("Failed to parse hex string, please try again.")

        print()

    assert False, "not reachable"


def show_yubikey_reset_warning_dialog() -> None:
    print_info_box(
        "WARNING - DANGER AHEAD",
        [
            "This action will reset the PIV interface of the connected YubiKey.",
            "All existing PIV data and keys will be irrevocably lost.",
            "",
            "Type 'CONTINUE' if you are sure to proceed.",
        ],
    )
    confirmation = prompt("Your Input: ")
    if confirmation != "CONTINUE":
        print("Aborted!")
        exit(1)


@with_single_connected_yubikey
def configure_single_yubikey(yubikey: YubiKey, passphrase: str, master_key: bytes, pin_attempts: int) -> None:
    print("Device info:")
    print(f" - Serial: {yubikey.serial}")
    print(f" - Firmware version: {yubikey.version}")
    print()
    print("DO NOT REMOVE YUBIKEY UNTIL CONFIGURATION IS COMPLETED.")
    time.sleep(2.5)
    print()
    print("Performing a factory reset of the PIV interface of the YubiKey.")
    print("All keys will be permanently deleted.")
    yubikey.reset()
    print("Factory reset completed, default pin and management key restored.")
    print()
    print("Configuring PIV interface:")
    print(f" 1. Setting number of pin attempts to {pin_attempts}... ", end="", flush=True)
    yubikey.set_pin_attempts(pin_attempts)
    print("Done.")
    print(" 2. Disabling PUK... Done.")
    print(" 3. Setting PIN (derived from passphrase)... ", end="", flush=True)
    seed = crypto.derive_seed(passphrase)
    pin = crypto.derive_pin(seed, yubikey.serial)
    yubikey.set_pin(pin)
    print("Done.")
    print(" 4. Locking down management operations (for future sessions)... ", end="", flush=True)
    yubikey.lock_management_operations()
    print("Done.")
    print()
    print(f"Generating new {yubikey.key_type} signing key on the YubiKey.")
    print("Please be patient, this may take a few seconds... ", end="", flush=True)
    yubikey.keygen()
    print("Done.")
    print()
    print("Preparing challenge/response protocol... ", end="", flush=True)
    challenge = crypto.derive_challenge(seed, yubikey.serial)
    print("Done.")
    print()
    # print("Please touch the YubiKey within 15 seconds after being prompted.")
    # input("Press ENTER to continue... ")
    # print()

    while True:
        try:
            signature = yubikey.sign(challenge, TouchInteraction("Pending signature authorization", "Authorized"))
            break
        except TimeoutError as e:
            reset_lines(4)
            error(f"{e}")
            print()
            prompt("Press ENTER to retry... ")
            reset_lines(5)

    response = hashlib.sha3_256(signature).digest()
    otp = crypto.xor_bytes(master_key, response)
    print()
    print("Storing master key one-time-pad to the YubiKey PIV interface... ", end="", flush=True)
    yubikey.store_object(otp)
    print("Done.")
    print()
    print("Configuration completed.")
    print("YubiKey can now be removed safely.")
    print()

    logger.debug(f"Passphrase: {passphrase}")
    logger.debug(f"Seed:       {seed.hex()}")
    logger.debug(f"PIN:        {pin.encode().hex()}")
    logger.debug(f"Challenge:  {challenge.hex()}")
    logger.debug(f"Response:   {response.hex()}")
    logger.debug(f"OTP:        {otp.hex()}")
    logger.debug(f"Master key: {master_key.hex()}")


@with_single_connected_yubikey
def get_master_key(yubikey: YubiKey, passphrase: str, attempt: int) -> tuple[bytes | None, int]:
    """Interacts with the YubiKey to derive a master key from the given passphrase."""
    attempts_remaining = yubikey.session.get_pin_attempts()
    if attempts_remaining == 1:
        print_info_box(
            "WARNING - LAST ATTEMPT",
            [
                "This is your last attempt to enter the passphrase correctly before the "
                "YubiKey will be locked and all data and keys will be irrevocable lost.",
                "",
                "Please re-enter your password for confirmation.",
            ],
        )
        repeat = passphrase_prompt("Confirm passphrase: ", "Passphrase re-entered.")
        print()
        if passphrase != repeat:
            error("Passphrases do not match.")
            print("Aborting.")
            exit(1)

        print("Passphrase confirmed successfully.")
        print("Proceeding.")

    seed = crypto.derive_seed(passphrase)
    pin = crypto.derive_pin(seed, yubikey.serial)
    challenge = crypto.derive_challenge(seed, yubikey.serial)

    logger.debug(f"Passphrase: {passphrase}")
    logger.debug(f"Seed:       {seed.hex()}")
    logger.debug(f"PIN:        {pin.encode().hex()}")
    logger.debug(f"Challenge:  {challenge.hex()}")

    try:
        yubikey.authenticate(pin)
    except InvalidPinError as e:
        if e.attempts_remaining > 0:
            reset_lines(3 if attempt > 1 else 2)

        match e.attempts_remaining:
            case 0:
                error(
                    "Passphrase invalid, no attempts remaining. "
                    "YubiKey has been locked and needs to be reconfigured."
                )
                exit(1)
            case 1:
                error("Passphrase invalid, only one attempt remaining.")
            case n:
                error(f"Passphrase invalid, {n} attempts remaining.")

        return None, 0

    signature = yubikey.sign(
        challenge,
        TouchInteraction("Running challenge/response protocol", "Done"),
    )

    print("Deriving master key... ", end="", flush=True)
    response = hashlib.sha3_256(signature).digest()
    otp = yubikey.load_object()
    master_key = crypto.xor_bytes(response, otp)
    print("Done.")

    logger.debug(f"Response:   {response.hex()}")
    logger.debug(f"OTP:        {otp.hex()}")
    logger.debug(f"Master key: {master_key.hex()}")

    return master_key, yubikey.serial


@click.group()
def kyu() -> None:
    """KeePassXC YubiKey Unlocker: An opinionated, personal CLI tool for protecting KeePassXC databases with a YubiKey.

    Under the hood, KeePassXC YubiKey Unlocker makes use of the YubiKey's PIV interface. It requires exclusive use of
    that interface and does interfere with other applications using the PIV interface. Other YubiKey applications
    (FIDO2, OpenPGP, ...) are not used. Thus, a single YubiKey may be safely shared between KeePassXC YubiKey Unlocker
    and those applications.
    """


def validate_attempts(ctx, param, value):
    if not (value is None or (1 <= value <= 255)):
        raise click.BadParameter("Number of unlock attempts must be between 1 and 255.")
    return value


@kyu.command()
@click.option(
    "--format",
    help=("Skip format prompt and use the specified format. " "[bytewords|bip39|hex]"),
    type=click.Choice(["bytewords", "bip39", "hex"]),
    required=False,
    show_default=True,
    metavar="FORMAT",
)
@click.option(
    "--attempts",
    help=(
        "Skip prompt and specify the number of unlock attempts before YubiKey will be locked directly. "
        "[min: 1, max: 255, default: 8]"
    ),
    type=int,
    show_default=False,
    metavar="ATTEMPTS",
    callback=validate_attempts,
)
@click.option(
    "--generate-key",
    help="Skip master key prompt and generate random key.",
    is_flag=True,
)
@click.option(
    "--force",
    help="Skip confirmation dialogs.",
    is_flag=True,
)
def configure(format: KeyFormat | None, attempts: int | None, generate_key: bool, force: bool) -> None:
    """Configure YubiKeys for the use with this tool."""
    print("Starting the KeePassXC YubiKey Unlocker configuration wizard.")
    print("Follow the steps below to protect a master key with a passphrase and the YubiKey.")
    if not force:
        show_yubikey_reset_warning_dialog()
    print()

    passphrase = checked_passphrase_prompt()
    master_key = master_key_prompt(format, generate_key or None)
    if master_key is None:
        master_key = secrets.token_bytes(32)
        cursor_up()
        clear_line()
        print("Using new random master key:")
        print(f" - hex: {master_key.hex()}")
        print(f" - bytewords: ", end="")
        words = bytewords.encode(master_key).split()
        for i, w in enumerate(words):
            if i == 0:
                print(f" 1. {w}", end="")
            elif i % 5 == 0:
                print(f"\n              {i+1: >2}. {w}", end="")
            else:
                print(f"   {i+1: >2}. {w}", end="")
        print()
        print()

    attempts = attempts or numeric_prompt(
        "What many wrong unlock attempts to allow before locking the YubiKey?",
        default=8,
        min=1,
        max=255,
    )

    while True:
        configure_single_yubikey(passphrase, master_key, attempts)
        if yes_no_prompt("Configure another YubiKey with the same passphrase and master key?", default="No"):
            print("Remove current key (if still inserted) and plug in next key to be configured.")
            prompt("Confirm by pressing ENTER when ready... ")
            print()
        else:
            print("Exiting.")
            break


@kyu.command(
    epilog="If no output format is specified, the recovered master key will be shown in all supported formats."
)
@click.option(
    "--format",
    type=click.Choice(["bytewords", "bip39", "hex"]),
    required=False,
    help="Output format for displaying the key.",
)
def recover(format: Literal["bytewords", "bip39", "hex"] | None) -> None:
    """Recover master key from passphrase and YubiKey."""
    master_key = None
    for i in itertools.count():
        passphrase = passphrase_prompt()
        master_key, _ = get_master_key(passphrase, attempt=i + 1)
        if master_key is not None:
            break
    assert master_key is not None

    if format == "hex":
        print()
        print("Recovered key:", master_key.hex())
        return

    formats: list[KeyFormat] = ["bytewords", "bip39"]
    if format is not None:
        formats = [format]

    for i, fmt in enumerate(formats):
        if i != 0:
            reset_line()

        words = encode_key(master_key, fmt).split()
        print_key_box(
            f"RECOVERED {fmt.upper()} KEY",
            words,
            master_key.hex(),
            fmt,
        )


@kyu.command()
@click.argument("database_path", type=click.Path(exists=True), required=False)
@click.option(
    "--format",
    type=click.Choice(["bytewords", "bip39", "hex"]),
    required=False,
    help="Key Format to use unlocking the database.",
)
def unlock(database_path: click.Path | None, format: KeyFormat | None) -> None:
    """Unlocks a KeePassXC database using a passphrase and a YubiKey.

    Database paths and key format can also be specified via the configuration file."""

    # print("KeePassXC YubiKey Unlocker")
    print(LOGO)
    try:
        cfg = config.load()
    except FileNotFoundError:
        cfg = config.DEFAULT_CONFIG
        print("Configuration file not found, using default database path and settings.")
        print()
    except Exception as e:
        error(f"Configuration file invalid. {e}")
        print("Exiting.")
        exit(1)

    yubikey_status = "No YubiKey detected."
    db_path = str(cfg.database_path)
    passphrase: str = ""

    master_key = None
    serial = None

    def print_status() -> None:
        print(f"{yubikey_status}")
        print(f"Database: {db_path}")
        print()
        print("Enter passphrase: ", end="", flush=True)

    def background_passphrase_prompt():
        nonlocal passphrase
        passphrase = getpass.getpass("")
        cursor_up()
        set_cursor_horizontal(19)

    changed = True

    for i in itertools.count():
        t = threading.Thread(target=background_passphrase_prompt, daemon=True)
        t.start()

        print_status()
        while t.is_alive():
            old = (yubikey_status, db_path)
            try:
                yukikey = YubiKey.get_unique_connected_yubikey()
                yubikey_status = f"YubiKey detected, serial: {yukikey.serial}"
                db_path = cfg.get_database_path(yukikey.serial)

            except YubiKeyError as e:
                yubikey_status = str(e)
                db_path = str(cfg.database_path)

            if database_path:
                db_path = str(database_path)

            changed = old != (yubikey_status, db_path)
            if changed:
                reset_lines(3)
                print_status()

            t.join(timeout=0.250)

        print("\rPassword entered.")
        master_key, serial = get_master_key(passphrase, attempt=i + 1)
        print()
        if master_key is not None:
            break

    assert master_key is not None
    assert serial is not None

    print("Opening database... ", end="", flush=True)
    unlock_phrase = encode_key(master_key, format or cfg.get_key_format(serial))
    keepassxc.open_database(unlock_phrase, pathlib.Path(db_path))
    print("Done.")


@kyu.command()
def version() -> None:
    """Display version information of this tool."""
    click.echo(f"KeePassXC YubiKey Unlocker: {importlib.metadata.version('kyu')}")
    click.echo("Libraries: ")
    for lib in ("click", "yubikey-manager"):
        click.echo(f" - {lib}: {importlib.metadata.version(lib)}")


@kyu.command(
    epilog=(
        "This results in the permanent deletion of all keys and data stored on the PIV interface. "
        "Other applications (FIDO2, OpenPGP, ...) are not affected."
    )
)
@click.option("--force", is_flag=True, help="Do not ask for confirmation.")
def wipe(force: bool) -> None:
    """Perform factory reset of a YubiKey's PIV interface."""

    @with_single_connected_yubikey
    def _wipe(yubikey: YubiKey) -> None:
        print("Executing wipe operation... ", end="", flush=True)
        yubikey.reset()
        print("Done. ")

    if not force:
        show_yubikey_reset_warning_dialog()
    print()
    _wipe()


@kyu.command(hidden=True)
def test() -> None:
    """Test command for development purposes only."""
    dev_mode = False
    try:
        dev_mode = subprocess.check_output(["git", "branch", "--show-current"], stderr=subprocess.DEVNULL) == b"dev\n"
    except Exception:
        pass

    if not dev_mode:
        print("Command for development purposes only.")
        print("Exiting.")
        exit(1)


_original_term_settings = None


def _save_term_settings():
    global _original_term_settings
    try:
        fd = sys.stdin.fileno()
        _original_term_settings = termios.tcgetattr(fd)
    except Exception:
        _original_term_settings = None


def _restore_term_settings():
    global _original_term_settings
    try:
        if _original_term_settings is not None:
            fd = sys.stdin.fileno()
            termios.tcsetattr(fd, termios.TCSADRAIN, _original_term_settings)
            _original_term_settings = None
    except Exception:
        pass


def main():
    # Save settings at startup & ensure restoration at exit.
    _save_term_settings()
    atexit.register(_restore_term_settings)

    if logger.level != logging.CRITICAL:
        print()
        print("!!! DEVELOPMENT MODE: LOGGING IS ENABLED !!!")
        print()

    kyu(prog_name=kyu.name)
