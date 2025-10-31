## CHANGE PIN command implementation
## Changes user PIN, PUK, or pairing secret

import ../keycard
import ../constants
import ../secure_apdu

type
  PinType* = enum
    UserPin = 0x00      ## User PIN (6 digits)
    Puk = 0x01          ## PUK (12 digits)
    PairingSecret = 0x02  ## Pairing secret (32 bytes)

  ChangePinError* = enum
    ChangePinOk
    ChangePinTransportError
    ChangePinInvalidFormat        # SW 0x6A80
    ChangePinInvalidP1            # SW 0x6A86
    ChangePinFailed
    ChangePinCapabilityNotSupported  # Credentials management capability required
    ChangePinSecureApduError
    ChangePinChannelNotOpen
    ChangePinConditionsNotMet     # PIN not verified or other precondition

  ChangePinResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: ChangePinError
      sw*: uint16

proc changePin*(card: var Keycard; pinType: PinType; newPin: seq[byte]): ChangePinResult =
  ## Change a PIN, PUK, or pairing secret
  ##
  ## Args:
  ##   pinType: Type of PIN to change (UserPin, Puk, or PairingSecret)
  ##   newPin: The new PIN/secret as byte sequence
  ##
  ## Preconditions:
  ##   - Secure channel must be open
  ##   - User PIN must be verified
  ##   - Credentials management capability required
  ##
  ## PIN Format Requirements:
  ##   - UserPin: 6 digits (6 bytes)
  ##   - Puk: 12 digits (12 bytes)
  ##   - PairingSecret: 32 bytes
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if PIN format is invalid
  ##   0x6A86 if P1 is invalid
  ##   0x6985 if conditions not met (PIN not verified)

  if not card.appInfo.hasCredentials():
    return ChangePinResult(success: false,
                          error: ChangePinCapabilityNotSupported,
                          sw: 0)

  if not card.secureChannel.open:
    return ChangePinResult(success: false,
                          error: ChangePinChannelNotOpen,
                          sw: 0)

  case pinType
  of UserPin:
    if newPin.len != 6:
      return ChangePinResult(success: false,
                            error: ChangePinInvalidFormat,
                            sw: 0x6A80'u16)
  of Puk:
    if newPin.len != 12:
      return ChangePinResult(success: false,
                            error: ChangePinInvalidFormat,
                            sw: 0x6A80'u16)
  of PairingSecret:
    if newPin.len != 32:
      return ChangePinResult(success: false,
                            error: ChangePinInvalidFormat,
                            sw: 0x6A80'u16)
  echo newPin
  echo pinType
  let secureResult = card.sendSecure(
    ins = InsChangeSecret,
    p1 = byte(pinType),
    data = newPin
  )

  if not secureResult.success:
    return ChangePinResult(success: false,
                          error: ChangePinSecureApduError,
                          sw: 0)

  case secureResult.sw
  of SwSuccess:
    return ChangePinResult(success: true)
  of 0x6A80:
    return ChangePinResult(success: false,
                          error: ChangePinInvalidFormat,
                          sw: secureResult.sw)
  of 0x6A86:
    return ChangePinResult(success: false,
                          error: ChangePinInvalidP1,
                          sw: secureResult.sw)
  of 0x6985:
    return ChangePinResult(success: false,
                          error: ChangePinConditionsNotMet,
                          sw: secureResult.sw)
  else:
    return ChangePinResult(success: false,
                          error: ChangePinFailed,
                          sw: secureResult.sw)
