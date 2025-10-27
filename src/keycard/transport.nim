import pcsc_shim as pcs
import pcsc/util as putil

import apdu
import constants

export ApduResponse

type
  TransportError* = enum
    TransportOk
    TransportNotConnected
    TransportResponseTooShort
    
  TransportResult*[T] = object
    case success*: bool
    of true:
      value*: T
    of false:
      error*: TransportError

  Transport* = ref object
    ctx: pcs.PcscContext
    card: pcs.PcscCard
    readerName*: string
    hasCard: bool

proc ok*[T](val: T): TransportResult[T] =
  TransportResult[T](success: true, value: val)

proc err*[T](e: TransportError): TransportResult[T] =
  TransportResult[T](success: false, error: e)

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

proc parseApduResponse(resp: openArray[byte]): TransportResult[ApduResponse] =
  if resp.len < 2:
    return err[ApduResponse](TransportResponseTooShort)
  let sw = (uint16(resp[^2]) shl 8) or uint16(resp[^1])
  let data = @resp[0 ..< resp.len-2]
  ok(ApduResponse(data: data, sw: sw))

proc transmit*(t: Transport; apdu: openArray[byte]): TransportResult[ApduResponse] =
  ## Transmit raw APDU bytes and return response
  ## Does not interpret status words - caller's responsibility
  if not t.hasCard:
    return err[ApduResponse](TransportNotConnected)
  let raw = t.card.transmit(@apdu)
  parseApduResponse(raw)

proc send*(t: Transport; apdu: Apdu): TransportResult[ApduResponse] =
  ## Send an APDU command object
  t.transmit(apdu.toBytes())

proc send*(t: Transport;
           ins: byte;
           cla: byte = ClaProprietary;
           p1: byte = 0x00;
           p2: byte = 0x00;
           data: openArray[byte] = []): TransportResult[ApduResponse] =
  ## Convenience: send APDU from parameters
  t.send(apdu(ins, cla, p1, p2, data))

proc transmitHex*(t: Transport; apduHex: string): TransportResult[ApduResponse] =
  ## Transmit APDU from hex string
  t.transmit(apduHex.fromHexLoose())

when defined(mockPcsc):
  proc mockCard*(t: Transport): pcs.PcscCard =
    t.card