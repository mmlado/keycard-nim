# tests/reset_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/reset_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/reset
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "RESET command":
  when defined(mockPcsc):
    test "reset sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to selected state (has public key)
      card.publicKey = repeat(byte(0xFF), 65)

      # Mock success response
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x90), 0x00]])

      let result = card.reset()

      # Verify RESET APDU was sent correctly
      # CLA = 0x80, INS = 0xFD, P1 = 0xAA, P2 = 0x55
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0] == @[byte(0x80), 0xFD, 0xAA, 0x55]

      # Verify result
      check result.success

    test "reset succeeds when card is selected":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to selected state (has public key)
      card.publicKey = repeat(byte(0xFF), 65)

      # Mock success response
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x90), 0x00]])

      let result = card.reset()

      check result.success

    test "reset fails when card not selected":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Don't set publicKey - card not selected
      # card.publicKey is empty

      let result = card.reset()

      check not result.success
      check result.error == ResetCardNotSelected

    test "reset handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set card to selected state (has public key)
      card.publicKey = repeat(byte(0xFF), 65)

      let result = card.reset()

      check not result.success
      check result.error == ResetTransportError

    test "reset handles failed SW":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to selected state (has public key)
      card.publicKey = repeat(byte(0xFF), 65)

      # Return error SW 0x6A82
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x82]])

      let result = card.reset()

      check not result.success
      check result.error == ResetFailed
      check result.sw == 0x6A82'u16

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
