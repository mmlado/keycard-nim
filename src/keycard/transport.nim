import pcsc_shim as pcs
import pcsc/util as putil

import apdu
from util import swHex

export ApduResponse

type
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
  result.sw = (uint16(resp[^2]) shl 8) or uint16(resp[^1])
  result.data = @resp[0 ..< resp.len-2]

proc transmit*(t: Transport; apdu: openArray[byte]): ApduResponse =
  if not t.hasCard:
    raise newException(IOError, "Not connected to a reader/card")
  let raw = t.card.transmit(@apdu)
  result = parseApduResponse(raw)

proc send*(t: Transport; apdu: Apdu): ApduResponse =
  ## Send an APDU command object
  t.transmit(apdu.toBytes())

proc send*(t: Transport;
           ins: byte;
           cla: byte = 0x00;
           p1: byte = 0x00;
           p2: byte = 0x00;
           data: openArray[byte] = []): ApduResponse =
  ## Convenience: send APDU from parameters
  t.send(apdu(ins, cla, p1, p2, data))


proc transmitHex*(t: Transport; apduHex: string): ApduResponse =
  t.transmit(apduHex.fromHexLoose())

proc transmitExpectOk*(t: Transport; apdu: openArray[byte]): seq[byte] =
  let r = t.transmit(apdu)
  if r.sw != 0x9000'u16:
    raise newException(IOError, "SW=" & swHex(r.sw))
  r.data

proc sendExpectOk*(t: Transport; apdu: Apdu): seq[byte] =
  ## Send APDU and expect SW=9000, return data or raise
  let r = t.send(apdu)
  if r.sw != 0x9000'u16:
    raise newException(IOError, "SW=" & swHex(r.sw))
  r.data

proc sendExpectOk*(t: Transport;
                   ins: byte;
                   cla: byte = 0x00;
                   p1: byte = 0x00;
                   p2: byte = 0x00;
                   data: openArray[byte] = []): seq[byte] =
  ## Convenience: send APDU from parameters and expect SW=9000
  t.sendExpectOk(apdu(ins, cla, p1, p2, data))

when defined(mockPcsc):
  proc mockCard*(t: Transport): pcs.PcscCard =
    t.card