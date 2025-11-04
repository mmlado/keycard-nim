## BER-TLV parsing utilities

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