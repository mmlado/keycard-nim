# Run with: nim r -d:mockPcsc --path:src tests/export_key_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/export_key
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "EXPORT KEY command":
  when defined(mockPcsc):
    test "export public key only sends correct APDU":
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
      let mockEncryptedData = repeat(byte(0xBB), 96)  # Enough for TLV data
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Export current key, public only
      discard card.exportKey(CurrentKey, PublicOnly)

      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC2)  # InsExportKey
      check tx[0][2] == byte(0x00)  # P1 = CurrentKey
      check tx[0][3] == byte(0x01)  # P2 = PublicOnly

    test "export with derivation path sends correct APDU":
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

      # Export with derivation: m/44'/60'/0'/0/0
      let path = @[
        uint32(0x8000002C),  # 44' (hardened)
        uint32(0x8000003C),  # 60' (hardened)
        uint32(0x80000000),  # 0' (hardened)
        uint32(0),           # 0
        uint32(0)            # 0
      ]
      discard card.exportKey(Derive, PublicOnly, path, DeriveMaster)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC2)  # InsExportKey
      check tx[0][2] == byte(0x01)  # P1 = Derive | DeriveMaster
      check tx[0][3] == byte(0x01)  # P2 = PublicOnly

    test "export with derive from current sends correct P1":
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

      # Derive from current with path
      let path = @[uint32(0), uint32(1)]
      discard card.exportKey(DeriveAndMakeCurrent, ExtendedPublic, path, DeriveCurrent)

      # Verify APDU
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC2)  # InsExportKey
      check tx[0][2] == byte(0x82)  # P1 = DeriveAndMakeCurrent (0x02) | DeriveCurrent (0x80)
      check tx[0][3] == byte(0x02)  # P2 = ExtendedPublic

    test "export private key sends correct P2":
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

      # Export private and public
      discard card.exportKey(CurrentKey, PrivateAndPublic)

      # Verify APDU
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][3] == byte(0x00)  # P2 = PrivateAndPublic

    test "export key handles private not exportable (0x6985)":
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

      # Return error SW 0x6985 (private key not exportable)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x69), 0x85]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.exportKey(CurrentKey, PrivateAndPublic)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xC2)  # InsExportKey

    test "export key handles invalid path (0x6A80)":
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

      # Return error SW 0x6A80 (malformed path)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x80]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let path = @[uint32(1), uint32(2)]
      discard card.exportKey(Derive, PublicOnly, path)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

    test "export key handles invalid params (0x6A86)":
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

      # Return error SW 0x6A86 (invalid P1/P2)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x86]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.exportKey(CurrentKey, PublicOnly)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

    test "export key checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00

      # Open secure channel
      card.secureChannel.open = true

      let result = card.exportKey(CurrentKey, PublicOnly)

      check not result.success
      check result.error == ExportKeyCapabilityNotSupported

    test "export key requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.exportKey(CurrentKey, PublicOnly)

      check not result.success
      check result.error == ExportKeyChannelNotOpen

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true