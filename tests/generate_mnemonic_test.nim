# Run with: nim r -d:mockPcsc --path:src tests/generate_mnemonic_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/generate_mnemonic
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "GENERATE MNEMONIC command":
  when defined(mockPcsc):
    test "generate mnemonic with default checksum size sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response: MAC + encrypted word indexes + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification, but we can check the APDU sent
      discard card.generateMnemonic()

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD2)  # InsGenerateMnemonic
      check tx[0][2] == byte(0x04)  # P1 = default checksum size (4)
      check tx[0][3] == byte(0x00)  # P2

    test "generate mnemonic with checksum size 8 sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 64)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Generate with checksum size 8 (24 words)
      discard card.generateMnemonic(checksumSize = 8)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD2)  # InsGenerateMnemonic
      check tx[0][2] == byte(0x08)  # P1 = checksum size 8
      check tx[0][3] == byte(0x00)  # P2

    test "generate mnemonic with checksum size 6 sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Generate with checksum size 6 (18 words)
      discard card.generateMnemonic(checksumSize = 6)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][2] == byte(0x06)  # P1 = checksum size 6

    test "generate mnemonic handles invalid checksum size (0x6A86)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6A86 (invalid P1)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x86]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.generateMnemonic(checksumSize = 5)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD2)  # InsGenerateMnemonic

    test "generate mnemonic rejects checksum size < 4":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true

      # Try to generate with invalid checksum size (too small)
      let result = card.generateMnemonic(checksumSize = 3)

      check not result.success
      check result.error == GenerateMnemonicInvalidChecksumSize

    test "generate mnemonic rejects checksum size > 8":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Open secure channel
      card.secureChannel.open = true

      # Try to generate with invalid checksum size (too large)
      let result = card.generateMnemonic(checksumSize = 9)

      check not result.success
      check result.error == GenerateMnemonicInvalidChecksumSize

    test "generate mnemonic checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00

      # Open secure channel
      card.secureChannel.open = true

      let result = card.generateMnemonic()

      check not result.success
      check result.error == GenerateMnemonicCapabilityNotSupported

    test "generate mnemonic requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.generateMnemonic()

      check not result.success
      check result.error == GenerateMnemonicChannelNotOpen

suite "Word index parsing":
  test "parse 12-word mnemonic (24 bytes)":
    # 12 words = 12 * 2 bytes = 24 bytes
    # Create test data with known values
    let data = @[
      byte(0x00), 0x00,  # Word 0
      byte(0x00), 0x01,  # Word 1
      byte(0x07), 0xFF,  # Word 2047 (max)
      byte(0x01), 0x00,  # Word 256
      byte(0x00), 0x10,  # Word 16
      byte(0x07), 0xFE,  # Word 2046
      byte(0x00), 0xFF,  # Word 255
      byte(0x04), 0x00,  # Word 1024
      byte(0x00), 0x20,  # Word 32
      byte(0x02), 0x00,  # Word 512
      byte(0x01), 0x50,  # Word 336
      byte(0x03), 0xAB   # Word 939
    ]

    let indexes = parseWordIndexes(data)

    check indexes.len == 12
    check indexes[0] == 0
    check indexes[1] == 1
    check indexes[2] == 2047
    check indexes[3] == 256
    check indexes[4] == 16
    check indexes[5] == 2046
    check indexes[6] == 255
    check indexes[7] == 1024
    check indexes[8] == 32
    check indexes[9] == 512
    check indexes[10] == 336
    check indexes[11] == 939

  test "parse 24-word mnemonic (48 bytes)":
    # 24 words = 24 * 2 bytes = 48 bytes
    let data = repeat(byte(0x01), 48)

    let indexes = parseWordIndexes(data)

    check indexes.len == 24
    # All should be 0x0101 = 257
    for i in 0..<24:
      check indexes[i] == 257

  test "parse empty data":
    let data: seq[byte] = @[]

    let indexes = parseWordIndexes(data)

    check indexes.len == 0

  test "parse single word":
    let data = @[byte(0x05), 0xDC]  # Word 1500

    let indexes = parseWordIndexes(data)

    check indexes.len == 1
    check indexes[0] == 1500

  test "parse odd number of bytes (incomplete last word)":
    # 5 bytes = 2 complete words + 1 incomplete byte (ignored)
    let data = @[byte(0x00), 0x10, byte(0x00), 0x20, byte(0xFF)]

    let indexes = parseWordIndexes(data)

    check indexes.len == 2
    check indexes[0] == 16
    check indexes[1] == 32

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true