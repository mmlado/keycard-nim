import strutils

import pcsc_shim as pcs
import pcsc/util as putil

type
  ApduResponse* = object
    data*: seq[byte]
    sw*: uint16

  Transport* = ref object
    ctx: pcs.PcscContext
    card: pcs.PcscCard
    readerName*: string
    hasCard: bool

proc newTransport*(): Transport =
  result = Transport()
  result.ctx = establishContext()

proc listReaders*(t: Transport): seq[string] =
  t.ctx.listReaders()

proc connect*(t: Transport; reader: string) =
  t.readerName = reader
  t.card = t.ctx.connect(reader)
  t.hasCard = true

proc close*(t: Transport) =
  if not t.hasCard:
    return
  pcs.disconnect(t.card)
  t.hasCard = false

proc parseApduResponse(resp: openArray[byte]): ApduResponse =
  if resp.len < 2:
    raise newException(IOError, "APDU response too short (no SW)")
  ApduResponse(
    sw: (uint16(resp[^2]) shl 8) or uint16(resp[^1]),
    data: @resp[0 ..< resp.len - 2]
  )

proc transmit*(t: Transport; apdu: openArray[byte]): ApduResponse =
  if not t.hasCard:
    raise newException(IOError, "Not connected to a reader/card")
  let raw = t.card.transmit(@apdu)
  result = parseApduResponse(raw)

proc swHex(sw: uint16): string =
  ## Avoids "target type is larger than source type" warning.
  toHex(uint32(sw), 4)

proc transmitHex*(t: Transport; apduHex: string): ApduResponse =
  t.transmit(apduHex.fromHexLoose())

proc transmitExpectOk*(t: Transport; apdu: openArray[byte]): seq[byte] =
  let r = t.transmit(apdu)
  if r.sw != 0x9000'u16:
    raise newException(IOError, "SW=" & swHex(r.sw))
  r.data


proc `$`*(r: ApduResponse): string =
  "data=" & r.data.prettyHex() & " sw=" & swHex(r.sw)

when defined(mockPcsc):
  proc mockCard*(t: Transport): pcs.PcscCard =
    t.card