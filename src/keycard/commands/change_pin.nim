## CHANGE PIN command implementation
## Changes user PIN, PUK, or pairing secret

import ../keycard
import ../constants
import ../secure_apdu
import ../crypto/utils
import ../util

type
  PinType* = enum
    UserPin = 0x00      ## User PIN (6-digit string)
    Puk = 0x01          ## PUK (12-digit string)
    PairingSecret = 0x02  ## Pairing secret (password string, derived via PBKDF2)

  ChangePinError* = enum
    ChangePinOk
    ChangePinTransportError
    ChangePinInvalidFormat
    ChangePinInvalidP1
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

proc changePin*(card: var Keycard; pinType: PinType; newValue: string): ChangePinResult =
  ## Change a PIN, PUK, or pairing secret
  ##
  ## Args:
  ##   pinType: Type of credential to change (UserPin, Puk, or PairingSecret)
  ##   newValue: The new value as a string
  ##     - UserPin: 6-digit PIN string (e.g., "123456")
  ##     - Puk: 12-digit PUK string (e.g., "123456789012")
  ##     - PairingSecret: Pairing password (will be derived to 32-byte token via PBKDF2)
  ##
  ## Preconditions:
  ##   - Secure channel must be open
  ##   - User PIN must be verified
  ##   - Credentials management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if format is invalid
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

  # Validate and convert based on type
  var data: seq[byte]
  
  case pinType
  of UserPin:
    if newValue.len != PinLength:
      return ChangePinResult(success: false,
                            error: ChangePinInvalidFormat,
                            sw: SwWrongData)
    data = stringToBytes(newValue)
      
  of Puk:
    if newValue.len != PukLength:
      return ChangePinResult(success: false,
                            error: ChangePinInvalidFormat,
                            sw: SwWrongData)
    data = stringToBytes(newValue)
      
  of PairingSecret:
    # Generate 32-byte token from password (same as init)
    data = generatePairingToken(newValue)

  let secureResult = card.sendSecure(
    ins = InsChangeSecret,
    p1 = byte(pinType),
    data = data
  )

  if not secureResult.success:
    return ChangePinResult(success: false,
                          error: ChangePinSecureApduError,
                          sw: 0)

  case secureResult.sw
  of SwSuccess:
    return ChangePinResult(success: true)
  of SwWrongData:
    return ChangePinResult(success: false,
                          error: ChangePinInvalidFormat,
                          sw: secureResult.sw)
  of SwIncorrectP1P2:
    return ChangePinResult(success: false,
                          error: ChangePinInvalidP1,
                          sw: secureResult.sw)
  of SwConditionsNotSatisfied:
    return ChangePinResult(success: false,
                          error: ChangePinConditionsNotMet,
                          sw: secureResult.sw)
  else:
    return ChangePinResult(success: false,
                          error: ChangePinFailed,
                          sw: secureResult.sw)