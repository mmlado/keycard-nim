## VERIFY PIN command implementation
## Verifies the user PIN

import ../keycard
import ../constants
import ../secure_apdu
import ../util

type
  VerifyPinError* = enum
    VerifyPinOk
    VerifyPinTransportError
    VerifyPinBlocked
    VerifyPinIncorrect
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
  let pinBytes = stringToBytes(pin)

  # Send VERIFY PIN command as secure APDU
  let secureResult = card.sendSecure(
    ins = InsVerifyPin,
    data = pinBytes
  )

  if not secureResult.success:
    # Map secure APDU error to verify pin error
    let verifyError = mapSecureApduError(
      secureResult.error,
      VerifyPinChannelNotOpen,
      VerifyPinTransportError,
      VerifyPinSecureApduError
    )
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
    if (secureResult.sw and SwVerificationFailedMask) == SwVerificationFailed:
      let retries = int(secureResult.sw and SwRetryCounterMask)

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