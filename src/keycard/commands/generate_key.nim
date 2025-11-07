## GENERATE KEY command implementation
## Generates and stores keys completely on card

import ../keycard
import ../constants
import ../secure_apdu

type
  GenerateKeyError* = enum
    GenerateKeyOk
    GenerateKeyTransportError
    GenerateKeyFailed
    GenerateKeyCapabilityNotSupported  # Key management capability required
    GenerateKeySecureApduError
    GenerateKeyChannelNotOpen
    GenerateKeyConditionsNotMet       # PIN not verified

  GenerateKeyResult* = object
    case success*: bool
    of true:
      keyUID*: seq[byte]  # SHA-256 of the public key
    of false:
      error*: GenerateKeyError
      sw*: uint16

proc generateKey*(card: var Keycard): GenerateKeyResult =
  ## Generate and store keys on the card
  ##
  ## Preconditions:
  ##   - Secure channel must be open
  ##   - User PIN must be verified
  ##   - Key management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##
  ## Response Data:
  ##   Key UID (SHA-256 of the public key)
  ##
  ## After execution, the card state is the same as if LOAD KEY was performed.

  checkCapability(card, card.appInfo.hasKeyManagement(), GenerateKeyResult, GenerateKeyCapabilityNotSupported)
  checkSecureChannelOpen(card, GenerateKeyResult, GenerateKeyChannelNotOpen)

  let secureResult = card.sendSecure(
    ins = InsGenerateKey,
  )

  if not secureResult.success:
    return GenerateKeyResult(success: false,
                            error: GenerateKeySecureApduError,
                            sw: 0)

  case secureResult.sw
  of SwSuccess:
    return GenerateKeyResult(success: true, keyUID: secureResult.data)
  of SwConditionsNotSatisfied:
    return GenerateKeyResult(success: false,
                            error: GenerateKeyConditionsNotMet,
                            sw: secureResult.sw)
  else:
    return GenerateKeyResult(success: false,
                            error: GenerateKeyFailed,
                            sw: secureResult.sw)