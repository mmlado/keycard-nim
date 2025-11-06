## UNPAIR command implementation
## Unpairs a client at the given pairing index

import ../keycard
import ../constants
import ../secure_apdu

type
  UnpairError* = enum
    UnpairOk
    UnpairTransportError
    UnpairSecurityConditionsNotMet
    UnpairInvalidIndex
    UnpairFailed
    UnpairChannelNotOpen
    UnpairSecureApduError

  UnpairResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: UnpairError
      sw*: uint16

proc unpair*(card: var Keycard; pairingIndex: byte): UnpairResult =
  ## Unpair a client at the given pairing index
  ##
  ## Args:
  ##   pairingIndex: Index of the pairing slot to unpair (0-4)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - User PIN must be verified
  ##
  ## This command is sent as an encrypted/MAC'd secure APDU.
  ##
  ## UNPAIR APDU:
  ##   CLA = 0x80
  ##   INS = 0x13
  ##   P1 = pairing index
  ##   P2 = 0x00
  ##
  ## Response SW (in decrypted response):
  ##   0x9000 on success
  ##   0x6985 if security conditions are not met (PIN not verified)
  ##   0x6A86 if the index is invalid

  if not card.secureChannel.open:
    return UnpairResult(success: false,
                       error: UnpairChannelNotOpen,
                       sw: 0)

  let secureResult = card.sendSecure(
    ins = InsUnpair,
    p1 = pairingIndex
  )

  if not secureResult.success:
    let unpairError = case secureResult.error
      of SecureApduChannelNotOpen:
        UnpairChannelNotOpen
      of SecureApduTransportError:
        UnpairTransportError
      of SecureApduInvalidMac:
        UnpairSecureApduError
      else:
        UnpairSecureApduError

    return UnpairResult(success: false,
                       error: unpairError,
                       sw: 0)

  case secureResult.sw
  of SwSuccess:
    return UnpairResult(success: true)
  of SwConditionsNotSatisfied:
    return UnpairResult(success: false,
                       error: UnpairSecurityConditionsNotMet,
                       sw: secureResult.sw)
  of SwIncorrectP1P2:
    return UnpairResult(success: false,
                       error: UnpairInvalidIndex,
                       sw: secureResult.sw)
  else:
    return UnpairResult(success: false,
                       error: UnpairFailed,
                       sw: secureResult.sw)
