## Utility functions for keycard operations

import strutils

proc swHex*(sw: uint16): string =
  ## Convert status word to hex string
  ## Avoids "target type is larger than source type" warning
  toHex(uint32(sw), 4)

proc encodeBip32Path*(path: openArray[uint32]): seq[byte] =
  ## Encode a BIP32 derivation path as big-endian bytes
  ## Each path component is encoded as 4 bytes (32-bit big-endian)
  ## Used by SIGN, EXPORT KEY, and DERIVE KEY commands
  result = newSeq[byte](path.len * 4)
  for i, value in path:
    let offset = i * 4
    result[offset] = byte((value shr 24) and 0xFF)
    result[offset + 1] = byte((value shr 16) and 0xFF)
    result[offset + 2] = byte((value shr 8) and 0xFF)
    result[offset + 3] = byte(value and 0xFF)

proc stringToBytes*(s: string): seq[byte] =
  ## Convert a string to a byte sequence
  ## Each character is converted to its byte value
  result = newSeq[byte](s.len)
  for i in 0..<s.len:
    result[i] = byte(s[i])