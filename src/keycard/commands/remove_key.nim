## REMOVE KEY command implementation
## Removes the key from the card
 
import ../keycard
import ../constants
import ../secure_apdu
 
type
  RemoveKeyError* = enum
    RemoveKeyOk
    RemoveKeyTransportError
    RemoveKeyFailed
    RemoveKeyCapabilityNotSupported  # Key management capability required
    RemoveKeySecureApduError
    RemoveKeyChannelNotOpen
    RemoveKeyConditionsNotMet       # PIN not verified
 
  RemoveKeyResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: RemoveKeyError
      sw*: uint16
 
proc removeKey*(card: var Keycard): RemoveKeyResult =
  ## Remove the key from the card
  ##
  ## Preconditions:
  ##   - Secure channel must be open
  ##   - User PIN must be verified
  ##   - Key management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##
  ## After execution, the card is in an uninitialized state.
  ## No signing operation is possible until a new LOAD KEY command is performed.
 
  # Check key management capability
  if not card.appInfo.hasKeyManagement():
    return RemoveKeyResult(success: false,
                          error: RemoveKeyCapabilityNotSupported,
                          sw: 0)
 
  # Check secure channel is open
  if not card.secureChannel.open:
    return RemoveKeyResult(success: false,
                          error: RemoveKeyChannelNotOpen,
                          sw: 0)
 
  # Send REMOVE KEY command via secure channel
  let secureResult = card.sendSecure(
    ins = InsRemoveKey,
  )
 
  if not secureResult.success:
    return RemoveKeyResult(success: false,
                          error: RemoveKeySecureApduError,
                          sw: 0)
 
  # Check status word
  case secureResult.sw
  of SwSuccess:
    return RemoveKeyResult(success: true)
  of SwConditionsNotSatisfied:
    return RemoveKeyResult(success: false,
                          error: RemoveKeyConditionsNotMet,
                          sw: secureResult.sw)
  else:
    return RemoveKeyResult(success: false,
                          error: RemoveKeyFailed,
                          sw: secureResult.sw)