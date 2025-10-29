# tests/ident_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/ident_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/ident
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "IDENT command":
  when defined(mockPcsc):
    test "ident sends correct APDU structure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Mock TLV response
      # Tag 0xA0 (signature template)
      #   Tag 0x8A (certificate - 98 bytes)
      #   Tag 0x30 (signature - 70 bytes)
      let mockCert = repeat(byte(0xAA), 98)
      let mockSig = repeat(byte(0xBB), 70)

      # Build inner TLV (0x8A + 0x30)
      var innerTlv: seq[byte] = @[
        0x8A'u8, byte(mockCert.len)
      ]
      innerTlv.add(mockCert)
      innerTlv.add(0x30'u8)
      innerTlv.add(byte(mockSig.len))
      innerTlv.add(mockSig)

      # Build outer TLV (0xA0)
      var outerTlv: seq[byte] = @[
        0xA0'u8, byte(innerTlv.len)
      ]
      outerTlv.add(innerTlv)
      outerTlv.add(@[byte(0x90), 0x00])  # SW

      t.mockCard().mockSetScriptedResponses(@[outerTlv])

      let result = card.ident()

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0x14 (InsIdent), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0x14)  # InsIdent
      check tx[0][2] == byte(0x00)  # P1
      check tx[0][3] == byte(0x00)  # P2
      check tx[0][4] == byte(0x20)  # LC = 32 (challenge)
      check tx[0].len == 5 + 32     # Header + 32-byte challenge

      # Check result
      check result.success
      check result.certificate.len == 98
      check result.signature.len == 70
      check result.publicKey.len == 33

    test "ident with custom challenge":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Custom challenge
      let customChallenge = repeat(byte(0xFF), 32)

      # Mock TLV response
      let mockCert = repeat(byte(0xAA), 98)
      let mockSig = repeat(byte(0xBB), 70)

      var innerTlv: seq[byte] = @[
        0x8A'u8, byte(mockCert.len)
      ]
      innerTlv.add(mockCert)
      innerTlv.add(0x30'u8)
      innerTlv.add(byte(mockSig.len))
      innerTlv.add(mockSig)

      var outerTlv: seq[byte] = @[
        0xA0'u8, byte(innerTlv.len)
      ]
      outerTlv.add(innerTlv)
      outerTlv.add(@[byte(0x90), 0x00])

      t.mockCard().mockSetScriptedResponses(@[outerTlv])

      let result = card.ident(customChallenge)

      # Verify custom challenge was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0].len == 5 + 32

      # Check that the challenge matches (starts at index 5)
      for i in 0..<32:
        check tx[0][5 + i] == byte(0xFF)

      check result.success

    test "ident handles invalid format (0x6A80)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Return error SW 0x6A80 (invalid format)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x80]])

      let result = card.ident()

      check not result.success
      check result.error == IdentInvalidFormat
      check result.sw == 0x6A80'u16

    test "ident handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      let result = card.ident()

      check not result.success
      check result.error == IdentTransportError

    test "ident handles malformed response":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Return response without proper TLV structure
      let badResponse = repeat(byte(0xAA), 10) & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[badResponse])

      let result = card.ident()

      check not result.success
      check result.error == IdentInvalidResponse

    test "ident extracts public key correctly":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Create certificate with known public key (first 33 bytes)
      var mockCert: seq[byte] = @[]
      # Compressed public key (33 bytes)
      for i in 0..<33:
        mockCert.add(byte(i))
      # Rest of certificate (65 bytes)
      mockCert.add(repeat(byte(0xCC), 65))

      let mockSig = repeat(byte(0xBB), 70)

      var innerTlv: seq[byte] = @[
        0x8A'u8, byte(mockCert.len)
      ]
      innerTlv.add(mockCert)
      innerTlv.add(0x30'u8)
      innerTlv.add(byte(mockSig.len))
      innerTlv.add(mockSig)

      var outerTlv: seq[byte] = @[
        0xA0'u8, byte(innerTlv.len)
      ]
      outerTlv.add(innerTlv)
      outerTlv.add(@[byte(0x90), 0x00])

      t.mockCard().mockSetScriptedResponses(@[outerTlv])

      let result = card.ident()

      check result.success
      check result.publicKey.len == 33
      # Verify first 33 bytes are extracted correctly
      for i in 0..<33:
        check result.publicKey[i] == byte(i)

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
