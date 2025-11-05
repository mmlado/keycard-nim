# Run with: nim r -d:mockPcsc --path:src tests/sign_test.nim
 
import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/sign
import keycard/constants
 
when defined(mockPcsc):
  import keycard/pcsc_shim
 
suite "SIGN command":
  when defined(mockPcsc):
    test "sign with current key sends correct APDU":
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
 
      # Mock response with scripted data
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 96)  # Enough for signature
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      # Sign a 32-byte hash
      let hash = repeat(byte(0x12), 32)
      discard card.sign(hash)
 
      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
 
      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC0)  # InsSign
      check tx[0][2] == byte(0x00)  # P1 = SignCurrentKey
      check tx[0][3] == byte(0x00)  # P2 = EcdsaSecp256k1
 
    test "sign with derivation path sends correct APDU":
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
      let mockEncryptedData = repeat(byte(0xBB), 96)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      # Sign with derivation: m/44'/60'/0'/0/0
      let hash = repeat(byte(0x12), 32)
      let path = @[
        uint32(0x8000002C),  # 44' (hardened)
        uint32(0x8000003C),  # 60' (hardened)
        uint32(0x80000000),  # 0' (hardened)
        uint32(0),           # 0
        uint32(0)            # 0
      ]
      discard card.sign(hash, SignDerive, EcdsaSecp256k1, path, DeriveMaster)
 
      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC0)  # InsSign
      check tx[0][2] == byte(0x01)  # P1 = SignDerive | DeriveMaster
      check tx[0][3] == byte(0x00)  # P2 = EcdsaSecp256k1
 
    test "sign with derive and make current sends correct P1":
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
      let mockEncryptedData = repeat(byte(0xBB), 96)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      # Sign with derive and make current
      let hash = repeat(byte(0x12), 32)
      let path = @[uint32(0), uint32(1)]
      discard card.sign(hash, SignDeriveAndMakeCurrent, EcdsaSecp256k1, path, DeriveCurrent)
 
      # Verify APDU
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC0)  # InsSign
      check tx[0][2] == byte(0x82)  # P1 = SignDeriveAndMakeCurrent (0x02) | DeriveCurrent (0x80)
      check tx[0][3] == byte(0x00)  # P2 = EcdsaSecp256k1
 
    test "sign handles data too short (0x6A80)":
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
 
      # Hash is too short (less than 32 bytes)
      let hash = repeat(byte(0x12), 16)
 
      let result = card.sign(hash)
 
      check not result.success
      check result.error == SignDataTooShort
 
    test "sign handles no PIN-less path (0x6A88)":
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
 
      # Return error SW 0x6A88 (no PIN-less path defined)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x88]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      let hash = repeat(byte(0x12), 32)
      discard card.sign(hash, SignPinlessPath)
 
      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
 
    test "sign handles algorithm not supported (0x6A81)":
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
 
      # Return error SW 0x6A81 (algorithm not supported)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x81]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      let hash = repeat(byte(0x12), 32)
      # Try EdDSA (not supported on Keycard)
      discard card.sign(hash, SignCurrentKey, EddsaEd25519)
 
      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][3] == byte(0x01)  # P2 = EddsaEd25519
 
    test "sign handles conditions not met (0x6985)":
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
 
      # Return error SW 0x6985 (conditions not met)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x69), 0x85]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])
 
      let hash = repeat(byte(0x12), 32)
      discard card.sign(hash)
 
      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
 
    test "sign checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
 
      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00
 
      # Open secure channel
      card.secureChannel.open = true
 
      let hash = repeat(byte(0x12), 32)
      let result = card.sign(hash)
 
      check not result.success
      check result.error == SignCapabilityNotSupported
 
    test "sign requires secure channel (except PIN-less)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")
 
      # Set key management capability
      card.appInfo.capabilities = 0x02
 
      # Secure channel is NOT open
      card.secureChannel.open = false
 
      let hash = repeat(byte(0x12), 32)
      let result = card.sign(hash)
 
      check not result.success
      check result.error == SignChannelNotOpen
 
when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
 