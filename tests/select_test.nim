# tests/select_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/select_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/select
import keycard/constants
import keycard/tlv
import keycard/types/application_info

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "SELECT command":
  when defined(mockPcsc):
    test "select sends correct APDU":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
      
      # Mock a simple pre-init response (just public key)
      let mockPubKey = repeat(byte(0xFF), 65)
      let mockResponse = @[byte(0x80), 0x41] & mockPubKey & @[byte(0x90), 0x00]
      
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
      
      let result = card.select()
      
      # Verify SELECT APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0] == @[byte(0x00), 0xA4, 0x04, 0x00, 0x08] & @KeycardAid
      
      # Verify result
      check result.success
      check card.publicKey.len == 65

    test "select parses pre-init response (public key only)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
      
      # Pre-init state: just tag 0x80 with 65-byte public key
      let mockPubKey = repeat(byte(0x01), 65)
      let mockResponse = @[byte(0x80), 0x41] & mockPubKey & @[byte(0x90), 0x00]
      
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
      
      let result = card.select()
      
      check result.success
      check result.info.publicKey.len == 65
      check result.info.publicKey[0] == 0x01
      check result.info.freeSlots == 0xFF  # Pre-init marker
      check not result.info.isInitialized()
      
      # Check card state
      check card.publicKey.len == 65
      check not card.isInitialized()

    test "select parses full initialized response":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
      
      # Build a full Application Info Template
      let instanceUid = repeat(byte(0x01), 16)
      let pubKey = repeat(byte(0x02), 65)
      let keyUid = repeat(byte(0x03), 32)
      
      var innerTlv: seq[byte] = @[]
      # Instance UID
      innerTlv.add @[byte(0x8F), 0x10] & instanceUid
      # Public Key
      innerTlv.add @[byte(0x80), 0x41] & pubKey
      # Version 2.1
      innerTlv.add @[byte(0x02), 0x02, 0x02, 0x01]
      # Free slots: 5
      innerTlv.add @[byte(0x02), 0x01, 0x05]
      # Key UID
      innerTlv.add @[byte(0x8E), 0x20] & keyUid
      # Capabilities: 0x0F (all capabilities)
      innerTlv.add @[byte(0x8D), 0x01, 0x0F]
      
      let mockResponse = @[byte(0xA4), byte(innerTlv.len)] & innerTlv & @[byte(0x90), 0x00]
      
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
      
      let result = card.select()
      
      check result.success
      check result.info.isInitialized()
      check result.info.instanceUid.len == 16
      check result.info.publicKey.len == 65
      check result.info.keyUid.len == 32
      check result.info.appVersion == (2'u8, 1'u8)
      check result.info.freeSlots == 5
      check result.info.capabilities == 0x0F
      
      # Test capability checks
      check result.info.hasSecureChannel()
      check result.info.hasKeyManagement()
      check result.info.hasCredentials()
      check result.info.hasNdef()
      
      # Check card state
      check card.isInitialized()
      check card.hasSecureChannel()
      check card.version() == (2'u8, 1'u8)

    test "select handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error
      
      let result = card.select()
      
      check not result.success
      check result.error == SelectTransportError
      check not card.selected

    test "select handles failed SW":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
      
      # Return error SW 0x6A82
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x82]])
      
      let result = card.select()
      
      check not result.success
      check result.error == SelectFailed
      check result.sw == 0x6A82'u16
      check not card.selected

suite "TLV parsing":
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

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true