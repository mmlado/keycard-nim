## UNBLOCK PIN command implementation
## Unblocks a blocked PIN using the PUK

import ../keycard
import ../constants
import ../secure_apdu

type
  UnblockPinError* = enum
    UnblockPinOk
    UnblockPinTransportError
    UnblockPinInvalidFormat       # SW 0x6A80 - data not 18 bytes
    UnblockPinWrongPuk            # SW 0x63CX - wrong PUK, X retries remaining
    UnblockPinBlocked             # SW 0x63C0 - PUK is blocked
    UnblockPinFailed
    UnblockPinCapabilityNotSupported  # Credentials management capability required
    UnblockPinSecureApduError
    UnblockPinChannelNotOpen

  UnblockPinResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: UnblockPinError
      sw*: uint16
      retriesRemaining*: int  # Only valid for UnblockPinWrongPuk

proc unblockPin*(card: var Keycard; puk: string; newPin: string): UnblockPinResult =
  ## Unblock a blocked PIN using the PUK
  ##
  ## Args:
  ##   puk: The PUK (12 digits)
  ##   newPin: The new PIN to set (6 digits)
  ##
  ## Preconditions:
  ##   - Secure channel must be open
  ##   - User PIN must be blocked
  ##   - Credentials management capability required
  ##
  ## Format Requirements:
  ##   - PUK must be exactly 12 digits
  ##   - New PIN must be exactly 6 digits
  ##   - Total data = 18 bytes
  ##
  ## UNBLOCK PIN APDU:
  ##   CLA = 0x80
  ##   INS = 0x22
  ##   P1 = 0x00
  ##   P2 = 0x00
  ##   Data = PUK (12 bytes) + new PIN (6 bytes)
  ##
  ## Response SW:
  ##   0x9000 on success (PIN unblocked, changed, and authenticated)
  ##   0x6A80 if format is invalid
  ##   0x63CX if PUK is wrong (X = remaining retries)
  ##   0x63C0 if PUK is blocked (wallet lost)

  # Check credentials management capability
  if not card.appInfo.hasCredentials():
    return UnblockPinResult(success: false,
                           error: UnblockPinCapabilityNotSupported,
                           sw: 0,
                           retriesRemaining: 0)

  # Check secure channel is open
  if not card.secureChannel.open:
    return UnblockPinResult(success: false,
                           error: UnblockPinChannelNotOpen,
                           sw: 0,
                           retriesRemaining: 0)

  # Validate format: PUK = 12 digits, PIN = 6 digits
  if puk.len != 12:
    return UnblockPinResult(success: false,
                           error: UnblockPinInvalidFormat,
                           sw: 0x6A80'u16,
                           retriesRemaining: 0)

  if newPin.len != 6:
    return UnblockPinResult(success: false,
                           error: UnblockPinInvalidFormat,
                           sw: 0x6A80'u16,
                           retriesRemaining: 0)

  # Build data: PUK + new PIN
  var data: seq[byte] = @[]
  for c in puk:
    data.add(byte(c))
  for c in newPin:
    data.add(byte(c))

  # Send UNBLOCK PIN command via secure channel
  let secureResult = card.sendSecure(
    ins = InsUnblockPin,
    p1 = 0x00,
    p2 = 0x00,
    data = data
  )

  if not secureResult.success:
    return UnblockPinResult(success: false,
                           error: UnblockPinSecureApduError,
                           sw: 0,
                           retriesRemaining: 0)

  # Check status word
  case secureResult.sw
  of SwSuccess:
    return UnblockPinResult(success: true)
  of 0x6A80:
    return UnblockPinResult(success: false,
                           error: UnblockPinInvalidFormat,
                           sw: secureResult.sw,
                           retriesRemaining: 0)
  else:
    # Check for 0x63CX (wrong PUK with retries)
    if (secureResult.sw and 0xFFF0'u16) == 0x63C0'u16:
      let retries = int(secureResult.sw and 0x000F'u16)
      if retries == 0:
        # PUK is blocked
        return UnblockPinResult(success: false,
                               error: UnblockPinBlocked,
                               sw: secureResult.sw,
                               retriesRemaining: 0)
      else:
        # Wrong PUK, retries remaining
        return UnblockPinResult(success: false,
                               error: UnblockPinWrongPuk,
                               sw: secureResult.sw,
                               retriesRemaining: retries)
    else:
      return UnblockPinResult(success: false,
                             error: UnblockPinFailed,
                             sw: secureResult.sw,
                             retriesRemaining: 0)