"""
Primary module for communication with the YubiKey, in particular with the PIV interface.
"""

from __future__ import annotations

import secrets
import typing
import warnings

from . import crypto

from ykman.base import YkmanDevice
from ykman.device import list_all_devices

from yubikit.core import TRANSPORT, NotSupportedError, InvalidPinError as InvalidPinError
from yubikit.core.smartcard import ApduError, SmartCardConnection
from yubikit.management import DeviceInfo, CAPABILITY
from yubikit.piv import PivSession, KEY_TYPE, MANAGEMENT_KEY_TYPE, PIN_POLICY, SLOT, TOUCH_POLICY


DEFAULT_PIN = "123456"
DEFAULT_MANAGEMENT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")

# Unused and pin-protected slot for storing the master key mask.
PIV_OBJECT_ID_MASTER_KEY_MASK = 0x005FC108  # facial image

# To ignore a deprecation warning for an unused reference to 3DES within the Yubico libraries.
warnings.filterwarnings("ignore", category=UserWarning)


class YubiKeyError(RuntimeError):
    pass


class NoYubiKeyDetectedError(YubiKeyError):
    def __init__(self):
        super().__init__("No YubiKey detected.")


class MultipleYubiKeysDetectedError(YubiKeyError):
    def __init__(self):
        super().__init__("Multiple YubiKeys detected.")


class TouchInteractionProtocol(typing.Protocol):
    def on_touched_requested(self) -> None: ...
    def on_operation_completed(self) -> None: ...


class YubiKey:
    """Primary class for all (PIV-related) interactions with the YubiKey."""

    def __init__(self, device: YkmanDevice, info: DeviceInfo):
        """Initializes a YubiKey instance. Typically, instances should be obtains via the
        `get_unique_connected_yubikey()` function.
        """
        if not info.supported_capabilities[TRANSPORT.USB] & CAPABILITY.PIV:
            raise RuntimeError("PIV capability required but disabled.")

        self.pin = DEFAULT_PIN
        self.management_key = DEFAULT_MANAGEMENT_KEY
        self.device = device
        self.version = info.version

        if info.serial is None:
            raise RuntimeError("Failed to read serial number from YubiKey.")
        self.serial = info.serial

        self.connection: SmartCardConnection
        self.session: PivSession
        self.key_type = KEY_TYPE.ED25519 if self.version >= (5, 7, 0) else KEY_TYPE.RSA2048

    @staticmethod
    def get_unique_connected_yubikey() -> YubiKey:
        """Check if there is exactly one YubiKey currently being connected. If this is the case, a YubiKey object for
        interacting with it is returned. Otherwise a RuntimeError is raised.
        """
        try:
            devices = list_all_devices()
        except Exception as e:
            raise YubiKeyError from e

        if len(devices) == 0:
            raise NoYubiKeyDetectedError
        if len(devices) >= 2:
            raise MultipleYubiKeysDetectedError

        return YubiKey(*devices[0])

    def __enter__(self) -> YubiKey:
        """Establishes a SmartCardConnection with the YubiKey."""
        # Maybe some secure connection is possible here, see _cli/util.py get_scp_params().
        self.connection = self.device.open_connection(SmartCardConnection)
        self.session = PivSession(self.connection)
        return self

    def __exit__(self, *args) -> None:
        """Ensures that the underlying SmartCardConnection with the YubiKey is closed."""
        self.connection.close()

    def reset(self) -> None:
        """Performs a factory reset of the PIV interface of the YubiKey. This results in the permanent deletion of all
        keys and data stored on the PIV interface. Other applications (FIDO2, OpenPGP, ...) are not affected.
        """
        self.session.reset()
        self.management_key = DEFAULT_MANAGEMENT_KEY
        self.pin = DEFAULT_PIN
        self.session.authenticate(self.management_key)
        self.session.verify_pin(self.pin)

    def set_pin_attempts(self, pin_attempts: int) -> None:
        """Sets the number of unsuccessful PIN attempts after which the YubiKey's PIV interface will be locked.
        Note: The implementation prevents PIN resets with a PUK (puk_attempts=0).
        """
        PUK_ATTEMPTS = 0
        self.session.set_pin_attempts(pin_attempts, PUK_ATTEMPTS)

    def set_pin(self, pin: str) -> None:
        """Sets the (derived) PIN to protect (certain keys and storage areas) of the YubiKey's PIV interface."""
        pin_bytes = pin.encode()
        if len(pin_bytes) != 8:
            raise ValueError("Invalid pin length.")

        self.session.change_pin(DEFAULT_PIN, pin)
        self.pin = pin

    def lock_management_operations(self) -> None:
        """Set a random management key for the YubiKey's PIV interface. After the current session has ended, this
        effectively locks down all management operations of the PIV interface.
        """
        try:
            self.management_key = secrets.token_bytes(32)
            self.session.set_management_key(MANAGEMENT_KEY_TYPE.AES256, self.management_key)
        except NotSupportedError:
            self.management_key = secrets.token_bytes(24)
            self.session.set_management_key(MANAGEMENT_KEY_TYPE.TDES, self.management_key)

    def keygen(self) -> None:
        """Generate a fresh signing key on the YubiKey's PIV interface. Depending on the firmware version of the device
        ED25519 (5.7.0 or higher) or RSA2048 is used for signing.
        """
        self.session.generate_key(SLOT.SIGNATURE, self.key_type, PIN_POLICY.ALWAYS, TOUCH_POLICY.ALWAYS)

    def authenticate(self, pin: str) -> None:
        """Authenticates a session by checking the provided PIN. If an invalid PIN is provided the internally tracked
        number of available PIN retries is reduced by the YubiKey.
        """
        self.session.verify_pin(pin)
        self.pin = pin

    def sign(self, challenge: bytes, touch_interaction: TouchInteractionProtocol | None = None) -> bytes:
        """Sign the given 32 byte challenge using the signing key stored on the YubiKey's PIV interface. For ED25519,
        no padding is required and the challenge is directly used as input. For RSA2048, EMSA-PKCS1-v1_5 is applied.
        In both cases, the signing operation is deterministic. The callback `on_touch_requested` is triggered, once
        the user should confirm the signing operation by touching the YubiKey. A TimeoutError is raised, if the user
        did not touch the YubiKey in time (timeout: ~15s).
        """
        if self.key_type == KEY_TYPE.RSA2048:
            challenge = crypto.rsa_pad_message(challenge, padded_length_in_bytes=2048 // 8)

        self.session.verify_pin(self.pin)
        if touch_interaction:
            touch_interaction.on_touched_requested()
        try:
            signature = self.session._use_private_key(SLOT.SIGNATURE, self.key_type, challenge, False)
            if touch_interaction:
                touch_interaction.on_operation_completed()
            return signature
        except ApduError:
            raise TimeoutError("Touch request timed out.")

    def store_object(self, data: bytes) -> None:
        """Stores the provided bytes (typically a small cryptographic secret, e.g., 32 bytes) in an unused and
        pin-protected slot of the YubiKey's PIV interface.
        """
        self.session.verify_pin(self.pin)
        self.session.put_object(PIV_OBJECT_ID_MASTER_KEY_MASK, data)

    def load_object(self) -> bytes:
        """Retrieves previously stored data (typically a small cryptographic secret, e.g., 32 bytes) from an unused and
        pin-protected slot of the YubiKey's PIV interface.
        """
        self.session.verify_pin(self.pin)
        return self.session.get_object(PIV_OBJECT_ID_MASTER_KEY_MASK)
