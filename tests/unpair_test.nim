# tests/unpair_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/unpair_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/unpair
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "UNPAIR command":
  when defined(mockPcsc):
    test "unpair sends correct APDU structure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response: encrypted SW 0x9000
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification, but we can check the APDU sent
      discard card.unpair(0)

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0x13 (InsUnpair), P1 = pairing index, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0x13)  # InsUnpair
      check tx[0][2] == byte(0x00)  # P1 = pairing index (0)
      check tx[0][3] == byte(0x00)  # P2

      # Data should be: MAC (16 bytes) + encrypted data
      let dataLen = int(tx[0][4])
      check dataLen >= 16  # At least MAC length
      check tx[0].len == 5 + dataLen  # Header + data

    test "unpair with different pairing index":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.unpair(3)  # Unpair index 3

      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][2] == byte(0x03)  # P1 should be 3

    test "unpair fails when secure channel not open":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.unpair(0)

      check not result.success
      check result.error == UnpairChannelNotOpen

    test "unpair handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      let result = card.unpair(0)

      check not result.success
      check result.error == UnpairTransportError

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true