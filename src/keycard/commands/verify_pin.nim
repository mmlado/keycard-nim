## VERIFY PIN command implementation
## Verifies the user PIN

import ../keycard
import ../constants
import ../secure_apdu

type
  VerifyPinError* = enum
    VerifyPinOk
    VerifyPinTransportError
    VerifyPinBlocked            # SW 0x63C0 - PIN is blocked
    VerifyPinIncorrect          # SW 0x63CX - Wrong PIN, X retries remaining
    VerifyPinFailed
    VerifyPinChannelNotOpen
    VerifyPinSecureApduError

  VerifyPinResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: VerifyPinError
      sw*: uint16
      retriesRemaining*: int  # Number of retries remaining (valid when error is VerifyPinIncorrect)

proc verifyPin*(card: var Keycard; pin: string): VerifyPinResult =
  ## Verify the user PIN
  ##
  ## Args:
  ##   pin: The PIN to verify (typically 6 digits)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##
  ## This command is sent as an encrypted/MAC'd secure APDU.
  ##
  ## VERIFY PIN APDU:
  ##   CLA = 0x80
  ##   INS = 0x20
  ##   P1 = 0x00
  ##   P2 = 0x00
  ##   Data = PIN bytes
  ##
  ## Response SW (in decrypted response):
  ##   0x9000 on success (PIN verified, retry counter reset)
  ##   0x63CX on failure, where X is the number of attempts remaining
  ##   0x63C0 when PIN is blocked (0 retries remaining)

  if not card.secureChannel.open:
    return VerifyPinResult(success: false,
                          error: VerifyPinChannelNotOpen,
                          sw: 0,
                          retriesRemaining: 0)

  # Convert PIN string to bytes
  let pinBytes = cast[seq[byte]](pin)

  # Send VERIFY PIN command as secure APDU
  let secureResult = card.sendSecure(
    ins = InsVerifyPin,
    cla = ClaProprietary,
    p1 = 0x00,
    p2 = 0x00,
    data = pinBytes
  )

  if not secureResult.success:
    # Map secure APDU error to verify pin error
    let verifyError = case secureResult.error
      of SecureApduChannelNotOpen:
        VerifyPinChannelNotOpen
      of SecureApduTransportError:
        VerifyPinTransportError
      of SecureApduInvalidMac:
        VerifyPinSecureApduError
      else:
        VerifyPinSecureApduError

    return VerifyPinResult(success: false,
                          error: verifyError,
                          sw: 0,
                          retriesRemaining: 0)

  # Check the real status word from decrypted response
  case secureResult.sw
  of SwSuccess:
    return VerifyPinResult(success: true)
  else:
    # Check if it's a 0x63CX response (incorrect PIN with retries)
    if (secureResult.sw and 0xFFF0'u16) == 0x63C0'u16:
      let retries = int(secureResult.sw and 0x000F'u16)

      if retries == 0:
        # PIN is blocked
        return VerifyPinResult(success: false,
                              error: VerifyPinBlocked,
                              sw: secureResult.sw,
                              retriesRemaining: 0)
      else:
        # Wrong PIN, but retries remaining
        return VerifyPinResult(success: false,
                              error: VerifyPinIncorrect,
                              sw: secureResult.sw,
                              retriesRemaining: retries)
    else:
      # Some other error
      return VerifyPinResult(success: false,
                            error: VerifyPinFailed,
                            sw: secureResult.sw,
                            retriesRemaining: 0)
