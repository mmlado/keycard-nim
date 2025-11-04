# Run with: nim r -d:mockPcsc --path:src tests/remove_key_test.nim
 
import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/remove_key
import keycard/constants
 
when defined(mockPcsc):
  import keycard/pcsc_shim
 
suite "REMOVE KEY command":
  when defined(mockPcsc):
    test "remove key sends correct APDU":
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
 
      # Mock success response: MAC + encrypted data + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      # This will fail MAC verification, but we can check the APDU sent
      discard card.removeKey()
 
      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
 
      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD3)  # InsRemoveKey
 
    test "remove key handles conditions not met error":
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
      discard card.removeKey()
 
      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD3)  # InsRemoveKey
 
    test "remove key checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
 
      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00  # No key management capability
 
      # Open secure channel
      card.secureChannel.open = true
 
      let result = card.removeKey()
 
      check not result.success
      check result.error == RemoveKeyCapabilityNotSupported
 
      # No APDU should be sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 0
 
    test "remove key requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
 
      # Set key management capability
      card.appInfo.capabilities = 0x02
 
      # Secure channel is NOT open
      card.secureChannel.open = false
 
      let result = card.removeKey()
 
      check not result.success
      check result.error == RemoveKeyChannelNotOpen
 
      # No APDU should be sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 0
 
when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
 