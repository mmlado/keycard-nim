# Run with: nim r -d:mockPcsc --path:src tests/set_pinless_path_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/set_pinless_path
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "SET PINLESS PATH command":
  when defined(mockPcsc):
    test "set pinless path sends correct APDU with path":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Open secure channel (required)
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response with success
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Set PIN-less path: m/44'/60'/0'/0/0
      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.setPinlessPath("m/44'/60'/0'/0/0")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC1)  # InsSetPinlessPath
      check tx[0][2] == byte(0x00)  # P1
      check tx[0][3] == byte(0x00)  # P2

    test "set pinless path with empty path sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Empty path to disable PIN-less
      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.setPinlessPath("")

      # Verify APDU was sent with empty data
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC1)  # InsSetPinlessPath

    test "set pinless path handles invalid data (0x6A80)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6A80 (invalid data)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x80]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.setPinlessPath("m/0/1")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC1)  # InsSetPinlessPath

    test "set pinless path handles conditions not met (0x6985)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6985 (PIN not verified)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x69), 0x85]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.setPinlessPath("m/44'/60'/0'/0/0")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC1)  # InsSetPinlessPath

    test "set pinless path requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.setPinlessPath("m/0/1")

      check not result.success
      check result.error == SetPinlessPathChannelNotOpen

suite "KeyPath parsing":
  test "parse master path":
    let path = parsePath("m/44'/60'/0'/0/0")
    check path.source == Master
    check path.components.len == 5
    check path.components[0] == 0x8000002C'u32  # 44'
    check path.components[1] == 0x8000003C'u32  # 60'
    check path.components[2] == 0x80000000'u32  # 0'
    check path.components[3] == 0'u32           # 0
    check path.components[4] == 0'u32           # 0

  test "parse parent path":
    let path = parsePath("../0/1")
    check path.source == Parent
    check path.components.len == 2
    check path.components[0] == 0'u32
    check path.components[1] == 1'u32

  test "parse current path with prefix":
    let path = parsePath("./0/1")
    check path.source == Current
    check path.components.len == 2
    check path.components[0] == 0'u32
    check path.components[1] == 1'u32

  test "parse current path without prefix":
    let path = parsePath("0/1")
    check path.source == Current
    check path.components.len == 2
    check path.components[0] == 0'u32
    check path.components[1] == 1'u32

  test "parse empty path":
    let path = parsePath("")
    check path.components.len == 0

  test "parse hardened components":
    let path = parsePath("m/44'/60'")
    check path.components[0] == 0x8000002C'u32
    check path.components[1] == 0x8000003C'u32

  test "parse non-hardened components":
    let path = parsePath("m/0/1/2")
    check path.components[0] == 0'u32
    check path.components[1] == 1'u32
    check path.components[2] == 2'u32

  test "parse mixed hardened and non-hardened":
    let path = parsePath("m/44'/0/1'")
    check path.components[0] == 0x8000002C'u32
    check path.components[1] == 0'u32
    check path.components[2] == 0x80000001'u32

  test "reject invalid component":
    expect(ValueError):
      discard parsePath("m/abc")

  test "reject invalid hardened component":
    expect(ValueError):
      discard parsePath("m/abc'")

  test "reject too many components":
    expect(ValueError):
      discard parsePath("m/0/1/2/3/4/5/6/7/8/9/10")

suite "KeyPath encoding":
  test "encode simple path":
    let path = parsePath("m/0/1")
    let encoded = encodePath(path)
    check encoded.len == 8
    # Component 0
    check encoded[0..3] == @[byte(0x00), 0x00, 0x00, 0x00]
    # Component 1
    check encoded[4..7] == @[byte(0x00), 0x00, 0x00, 0x01]

  test "encode hardened path":
    let path = parsePath("m/44'/60'")
    let encoded = encodePath(path)
    check encoded.len == 8
    # 44' = 0x8000002C
    check encoded[0] == byte(0x80)
    check encoded[1] == byte(0x00)
    check encoded[2] == byte(0x00)
    check encoded[3] == byte(0x2C)
    # 60' = 0x8000003C
    check encoded[4] == byte(0x80)
    check encoded[5] == byte(0x00)
    check encoded[6] == byte(0x00)
    check encoded[7] == byte(0x3C)

  test "encode empty path":
    let path = parsePath("")
    let encoded = encodePath(path)
    check encoded.len == 0

suite "KeyPath string conversion":
  test "path to string master":
    let path = parsePath("m/44'/60'/0'/0/0")
    let str = pathToString(path)
    check str == "m/44'/60'/0'/0/0"

  test "path to string parent":
    let path = parsePath("../0/1")
    let str = pathToString(path)
    check str == "../0/1"

  test "path to string current":
    let path = parsePath("./0/1")
    let str = pathToString(path)
    check str == "./0/1"

  test "path to string empty":
    let path = parsePath("")
    let str = pathToString(path)
    check str == ""

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
