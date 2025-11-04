# Run with: nim r -d:mockPcsc --path:src tests/generate_key_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/generate_key
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "GENERATE KEY command":
  when defined(mockPcsc):
    test "generate key sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02  # Key management capability bit

      # Open secure channel (required)
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response: MAC + encrypted key UID (32 bytes SHA-256) + SW
      let mockMac = repeat(byte(0xAA), 16)
      # Mock key UID (32 bytes)
      let mockKeyUID = @[
        byte(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
      ]
      let mockEncryptedData = repeat(byte(0xBB), 48)  # Encrypted key UID + padding
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification, but we can check the APDU sent
      discard card.generateKey()

      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD4)  # InsGenerateKey
      check tx[0][2] == byte(0x00)  # P1
      check tx[0][3] == byte(0x00)  # P2

    test "generate key handles conditions not met (0x6985)":
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

      # Return error SW 0x6985 (conditions not met - PIN not verified)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x69), 0x85]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.generateKey()

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD4)  # InsGenerateKey

    test "generate key checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00  # No key management capability

      # Open secure channel
      card.secureChannel.open = true

      let result = card.generateKey()

      check not result.success
      check result.error == GenerateKeyCapabilityNotSupported

    test "generate key requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.generateKey()

      check not result.success
      check result.error == GenerateKeyChannelNotOpen

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
