## BER-TLV parsing utilities

type
  TlvTag* = object
    tag*: byte
    value*: seq[byte]

proc parseTlv*(data: openArray[byte]): seq[TlvTag] =
  ## Parse BER-TLV encoded data into a sequence of tags
  result = @[]
  var pos = 0
  
  while pos < data.len:
    if pos + 1 >= data.len:
      break  # Not enough data for tag + length
    
    let tag = data[pos]
    inc pos
    
    let length = int(data[pos])
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
  false