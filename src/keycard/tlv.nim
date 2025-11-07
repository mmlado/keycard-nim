## BER-TLV parsing and encoding utilities

import constants

type
  TlvTag* = object
    tag*: byte
    value*: seq[byte]

proc parseTlv*(data: openArray[byte]): seq[TlvTag] =
  ## Parse BER-TLV encoded data into a sequence of tags
  ## Supports multi-byte length encoding per ISO/IEC 7816-4
  result = @[]
  var pos = 0

  while pos < data.len:
    if pos + 1 >= data.len:
      break  # Not enough data for tag + length

    let tag = data[pos]
    inc pos

    # Parse BER-TLV length
    var length: int
    let firstLengthByte = data[pos]
    inc pos

    if (firstLengthByte and 0x80) == 0:
      # Short form: length is 0-127 (bit 7 = 0)
      length = int(firstLengthByte)
    else:
      # Long form: bit 7 = 1, bits 6-0 indicate number of subsequent length bytes
      let numLengthBytes = int(firstLengthByte and 0x7F)

      if numLengthBytes == 0 or pos + numLengthBytes > data.len:
        break  # Invalid or not enough data for length bytes

      length = 0
      for i in 0 ..< numLengthBytes:
        length = (length shl 8) or int(data[pos])
        inc pos

    if pos + length > data.len:
      break  # Not enough data for value

    let value = data[pos ..< pos + length]
    result.add(TlvTag(tag: tag, value: @value))
    pos += length

proc findTag*(tags: seq[TlvTag], tag: byte): seq[byte] =
  ## Find a tag and return its value, or empty seq if not found
  for t in tags:
    if t.tag == tag:
      return t.value
  @[]

proc hasTag*(tags: seq[TlvTag], tag: byte): bool =
  ## Check if a tag exists
  for t in tags:
    if t.tag == tag:
      return true

proc encodeTlv*(tag: byte, value: openArray[byte]): seq[byte] =
  ## Encode a single TLV tag
  ## Supports multi-byte length encoding per ISO/IEC 7816-4
  result = @[tag]

  let length = value.len

  if length <= 127:
    # Short form: single byte length
    result.add(byte(length))
  else:
    # Long form: first byte has bit 7 set, bits 6-0 indicate number of length bytes
    # For lengths up to 255, we need 1 length byte
    # For lengths up to 65535, we need 2 length bytes
    if length <= MaxApduDataLength:
      result.add(0x81'u8)  # 1 length byte follows
      result.add(byte(length))
    else:
      result.add(0x82'u8)  # 2 length bytes follow
      result.add(byte((length shr 8) and 0xFF))
      result.add(byte(length and 0xFF))

  result.add(@value)

proc encodeKeypairTemplate*(
  publicKey: openArray[byte],
  privateKey: openArray[byte],
  chainCode: openArray[byte] = []
): seq[byte] =
  ## Encode a keypair template with Tag 0xA1
  ## Contains:
  ##   Tag 0x80 = public key (optional, can be empty)
  ##   Tag 0x81 = private key (required)
  ##   Tag 0x82 = chain code (optional, only for extended keypair)

  var inner: seq[byte] = @[]

  # Add public key if provided
  if publicKey.len > 0:
    inner.add(encodeTlv(TagTlvPublicKey, publicKey))

  # Add private key (required)
  inner.add(encodeTlv(TagTlvPrivateKey, privateKey))

  # Add chain code if provided (for extended keypair)
  if chainCode.len > 0:
    inner.add(encodeTlv(TagTlvChainCode, chainCode))

  # Wrap in Tag 0xA1 template
  result = encodeTlv(TagKeypairTemplate, inner)
