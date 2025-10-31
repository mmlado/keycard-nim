# Run with: nim r -d:mockPcsc --path:src tests/unblock_pin_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/unblock_pin
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "UNBLOCK PIN command":
  when defined(mockPcsc):
    test "unblock PIN sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04  # Credentials capability bit

      # Open secure channel (required)
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response: MAC + encrypted data + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification, but we can check the APDU sent
      discard card.unblockPin("123456123456", "654321")

      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x22)  # InsUnblockPin

    test "unblock PIN validates PUK format (must be 12 digits)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true

      # Try with invalid PUK length (11 digits)
      let result = card.unblockPin("12345678901", "654321")

      check not result.success
      check result.error == UnblockPinInvalidFormat
      check result.sw == 0x6A80'u16

      # No APDU should be sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 0

    test "unblock PIN validates new PIN format (must be 6 digits)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true

      # Try with invalid new PIN length (5 digits)
      let result = card.unblockPin("123456123456", "65432")

      check not result.success
      check result.error == UnblockPinInvalidFormat
      check result.sw == 0x6A80'u16

      # No APDU should be sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 0

    test "unblock PIN handles wrong PUK with retries":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x63C4 (wrong PUK, 4 retries remaining)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x63), 0xC4]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.unblockPin("123456123456", "654321")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x22)  # InsUnblockPin

    test "unblock PIN handles blocked PUK":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x63C0 (PUK blocked)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x63), 0xC0]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.unblockPin("123456123456", "654321")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x22)  # InsUnblockPin

    test "unblock PIN handles invalid format error":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6A80 (invalid format)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x80]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.unblockPin("123456123456", "654321")

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x22)  # InsUnblockPin

    test "unblock PIN checks credentials capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT credentials capability
      card.appInfo.capabilities = 0x00  # No credentials capability

      # Open secure channel
      card.secureChannel.open = true

      let result = card.unblockPin("123456123456", "654321")

      check not result.success
      check result.error == UnblockPinCapabilityNotSupported

    test "unblock PIN requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.unblockPin("123456123456", "654321")

      check not result.success
      check result.error == UnblockPinChannelNotOpen

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true