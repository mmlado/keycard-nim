## FACTORY_RESET command implementation
## Factory resets the Keycard applet on the card

import ../constants
import ../keycard

type
  ResetError* = enum
    ResetOK
    ResetTransportError
    ResetFailed
    ResetCardNotSelected

  ResetResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: ResetError
      sw*: uint16

proc reset*(card: var Keycard): ResetResult =
  ## Send Reset command to the selected Keycard applet
  if card.publicKey.len == 0:
    return ResetResult(success: false, error: ResetCardNotSelected)

  let transportResult = card.transport.send(
    ins = InsFactoryReset,
    p1 = 0xAA,
    p2 = 0x55
  )

  if not transportResult.success:
    return ResetResult(success: false, error: ResetTransportError)

  let resp = transportResult.value

  if resp.sw != SwSuccess:
    return ResetResult(success: false, error: ResetFailed, sw: resp.sw)

  ResetResult(success: true)