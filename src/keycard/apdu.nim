## APDU construction and response handling
## Idiomatic Nim style with default parameters
import pcsc/util as putil

import util

type
  ApduResponse* = object
    ## Response from a card after transmitting an APDU
    data*: seq[byte]
    sw*: uint16

  Apdu* = object
    ## APDU command structure
    cla*: byte
    ins*: byte
    p1*: byte
    p2*: byte
    data*: seq[byte]

proc apdu*(ins: byte;
           cla: byte = 0x80;
           p1: byte = 0x00;
           p2: byte = 0x00;
           data: openArray[byte] = []): Apdu =
  ## Create a new APDU. Only `ins` is required, others have sensible defaults.
  ## 
  ## Example:
  ##   let cmd = apdu(ins = 0xA4)  # Uses default cla=0x00, p1=0x00, p2=0x00
  ##   let cmd2 = apdu(ins = 0xA4, p1 = 0x04, data = @[0xA0'u8, 0x00])
  Apdu(cla: cla, ins: ins, p1: p1, p2: p2, data: @data)

proc toBytes*(a: Apdu): seq[byte] =
  ## Serialize APDU to byte sequence for transmission
  ## Uses short APDU format (Lc up to 255 bytes)
  result = @[a.cla, a.ins, a.p1, a.p2]
  
  if a.data.len > 0:
    if a.data.len > 255:
      raise newException(ValueError, "APDU data exceeds 255 bytes")
    result.add byte(a.data.len)  # Lc
    result.add a.data

proc encodeLv*(data: openArray[byte]): seq[byte] =
  ## Encode data in Length-Value format
  ## Length is a single byte, so max 255 bytes
  if data.len > 255:
    raise newException(ValueError, "LV encoding limited to 255 bytes")
  result = @[byte(data.len)]
  result.add @data

proc `$`*(r: ApduResponse): string =
  ## Pretty print an APDU response
  "ApduResponse(data=" & r.data.prettyHex() & ", sw=0x" & swHex(r.sw) & ")"