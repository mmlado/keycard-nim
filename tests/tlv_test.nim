# Run with: nim r -d:mockPcsc --path:src tests/tlv_test.nim

import std/unittest
import std/sequtils
import keycard/tlv
import keycard/transport
import keycard/keycard

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "TLV encoding":
  test "parseTlv handles simple tags":
    let data = @[byte(0x80), 0x02, 0xAB, 0xCD,
                 byte(0x81), 0x01, 0xFF]
    
    let tags = parseTlv(data)
    
    check tags.len == 2
    check tags[0].tag == 0x80
    check tags[0].value == @[byte(0xAB), 0xCD]
    check tags[1].tag == 0x81
    check tags[1].value == @[byte(0xFF)]

  test "findTag returns correct value":
    let data = @[byte(0x80), 0x02, 0xAB, 0xCD,
                 byte(0x81), 0x01, 0xFF]
    let tags = parseTlv(data)
    
    check tags.findTag(0x80) == @[byte(0xAB), 0xCD]
    check tags.findTag(0x81) == @[byte(0xFF)]
    check tags.findTag(0x82).len == 0  # Not found

  test "hasTag checks existence":
    let data = @[byte(0x80), 0x02, 0xAB, 0xCD]
    let tags = parseTlv(data)
    
    check tags.hasTag(0x80)
    check not tags.hasTag(0x81)

  test "parseTlv handles multi-byte length (0x81 form)":
    # Test tag with 129 bytes value (requires 0x81 0x81 encoding)
    var data: seq[byte] = @[byte(0xA4), 0x81, 0x81]  # Tag 0xA4, length = 129 bytes
    data.add repeat(byte(0xAA), 129)  # 129 bytes of 0xAA
    
    let tags = parseTlv(data)
    
    check tags.len == 1
    check tags[0].tag == 0xA4
    check tags[0].value.len == 129
    check tags[0].value[0] == 0xAA
    check tags[0].value[128] == 0xAA

  test "parseTlv handles multi-byte length (0x82 form)":
    # Test tag with 300 bytes value (requires 0x82 0x01 0x2C encoding)
    var data: seq[byte] = @[byte(0xA4), 0x82, 0x01, 0x2C]  # Tag 0xA4, length = 300 bytes
    data.add repeat(byte(0xBB), 300)  # 300 bytes of 0xBB
    
    let tags = parseTlv(data)
    
    check tags.len == 1
    check tags[0].tag == 0xA4
    check tags[0].value.len == 300
    check tags[0].value[0] == 0xBB
    check tags[0].value[299] == 0xBB

  test "parseTlv handles mixed short and long length forms":
    # Mix of short form (< 128) and long form (>= 128)
    var data: seq[byte] = @[]
    
    # First tag: short form, 10 bytes
    data.add @[byte(0x80), 0x0A]
    data.add repeat(byte(0x01), 10)
    
    # Second tag: long form 0x81, 200 bytes
    data.add @[byte(0x81), 0x81, 0xC8]
    data.add repeat(byte(0x02), 200)
    
    # Third tag: short form, 5 bytes
    data.add @[byte(0x82), 0x05]
    data.add repeat(byte(0x03), 5)
    
    let tags = parseTlv(data)
    
    check tags.len == 3
    check tags[0].tag == 0x80
    check tags[0].value.len == 10
    check tags[0].value[0] == 0x01
    
    check tags[1].tag == 0x81
    check tags[1].value.len == 200
    check tags[1].value[0] == 0x02
    
    check tags[2].tag == 0x82
    check tags[2].value.len == 5
    check tags[2].value[0] == 0x03

  test "encode short length TLV":
    let value = @[byte(0x01), 0x02, 0x03]
    let encoded = encodeTlv(0x80, value)

    # Should be: tag (1 byte) + length (1 byte) + value (3 bytes)
    check encoded.len == 5
    check encoded[0] == 0x80  # Tag
    check encoded[1] == 0x03  # Length
    check encoded[2..4] == value

  test "encode medium length TLV (1-byte length encoding)":
    let value = repeat(byte(0xAA), 200)
    let encoded = encodeTlv(0x81, value)

    # Should be: tag (1 byte) + 0x81 (1 byte) + length (1 byte) + value (200 bytes)
    check encoded.len == 203
    check encoded[0] == 0x81  # Tag
    check encoded[1] == 0x81  # Long form indicator (1 length byte)
    check encoded[2] == 200   # Length

  test "encode long length TLV (2-byte length encoding)":
    let value = repeat(byte(0xBB), 300)
    let encoded = encodeTlv(0x82, value)

    # Should be: tag (1 byte) + 0x82 (1 byte) + length (2 bytes) + value (300 bytes)
    check encoded.len == 304
    check encoded[0] == 0x82  # Tag
    check encoded[1] == 0x82  # Long form indicator (2 length bytes)
    check encoded[2] == 0x01  # Length high byte
    check encoded[3] == 0x2C  # Length low byte (0x012C = 300)

  test "encode keypair template with public and private keys":
    let publicKey = repeat(byte(0x04), 65)
    let privateKey = repeat(byte(0x01), 32)

    let temp = encodeKeypairTemplate(publicKey, privateKey)

    # Verify it's wrapped in Tag 0xA1
    check temp[0] == 0xA1

  test "encode keypair template without public key":
    let privateKey = repeat(byte(0x01), 32)

    let temp = encodeKeypairTemplate([], privateKey)

    # Verify it's wrapped in Tag 0xA1
    check temp[0] == 0xA1
    # Should contain only Tag 0x81 (private key), not Tag 0x80 (public key)

  test "encode extended keypair template with chain code":
    let publicKey = repeat(byte(0x04), 65)
    let privateKey = repeat(byte(0x01), 32)
    let chainCode = repeat(byte(0x03), 32)

    let temp = encodeKeypairTemplate(publicKey, privateKey, chainCode)

    # Verify it's wrapped in Tag 0xA1
    check temp[0] == 0xA1

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true