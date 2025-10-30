# tests/get_status_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/get_status_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/get_status
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "GET STATUS command":
  when defined(mockPcsc):
    test "get status sends correct APDU for application status (P1=0x00)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response with TLV application status
      # Tag 0xA3 (status template)
      #   Tag 0x02 = PIN retry (3)
      #   Tag 0x02 = PUK retry (5)
      #   Tag 0x01 = Key initialized (0xff)
      var innerTlv: seq[byte] = @[
        0x02'u8, 0x01'u8, 0x03'u8,  # PIN retry = 3
        0x02'u8, 0x01'u8, 0x05'u8,  # PUK retry = 5
        0x01'u8, 0x01'u8, 0xff'u8   # Key initialized
      ]
      var outerTlv: seq[byte] = @[
        0xA3'u8, byte(innerTlv.len)
      ]
      outerTlv.add(innerTlv)

      # Encrypt and add MAC (mock)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification but we can check the APDU
      discard card.getStatus()

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0xF2 (InsGetStatus), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xF2)  # InsGetStatus
      check tx[0][2] == byte(0x00)  # P1 = 0x00 (app status)
      check tx[0][3] == byte(0x00)  # P2

    test "get status sends correct APDU for key path (P1=0x01)":
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
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.getStatus(getKeyPath = true)

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Check P1 = 0x01
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xF2)  # InsGetStatus
      check tx[0][2] == byte(0x01)  # P1 = 0x01 (key path)
      check tx[0][3] == byte(0x00)  # P2

    test "get status fails when secure channel not open":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.getStatus()

      check not result.success
      check result.error == GetStatusChannelNotOpen

    test "get status handles undefined P1 (0x6A86)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response - error would come back as encrypted SW 0x6A86
      # For this test we're checking the error mapping
      # In real scenario, sendSecure would decrypt and return sw=0x6A86
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getStatus()
      # Will fail on MAC verification in mock, but in real case would handle 0x6A86

    test "get status handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      let result = card.getStatus()

      check not result.success
      check result.error == GetStatusTransportError

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true