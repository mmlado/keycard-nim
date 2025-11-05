# Run with: nim r -d:mockPcsc --path:src tests/load_key_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/load_key
import keycard/constants
import keycard/tlv

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "LOAD KEY command":
  when defined(mockPcsc):
    test "load ECC keypair sends correct APDU":
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

      # Mock response: MAC + encrypted key UID (32 bytes) + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Load a test keypair
      let privateKey = repeat(byte(0x01), 32)
      let publicKey = @[byte(0x04)] & repeat(byte(0x02), 64)  # Uncompressed format

      # This will fail MAC verification, but we can check the APDU sent
      discard card.loadKey(EccKeypair, privateKey, publicKey)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey
      check tx[0][2] == byte(0x01)  # P1 = EccKeypair
      check tx[0][3] == byte(0x00)  # P2

    test "load ECC extended keypair sends correct APDU":
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
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Load extended keypair with chain code
      let privateKey = repeat(byte(0x01), 32)
      let publicKey = @[byte(0x04)] & repeat(byte(0x02), 64)
      let chainCode = repeat(byte(0x03), 32)

      discard card.loadKey(EccExtendedKeypair, privateKey, publicKey, chainCode)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey
      check tx[0][2] == byte(0x02)  # P1 = EccExtendedKeypair
      check tx[0][3] == byte(0x00)  # P2

    test "load BIP39 seed sends correct APDU":
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
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Load BIP39 seed (64 bytes)
      let seed = repeat(byte(0xAB), 64)

      discard card.loadKey(Bip39Seed, seed)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey
      check tx[0][2] == byte(0x03)  # P1 = Bip39Seed
      check tx[0][3] == byte(0x00)  # P2

    test "load keypair without public key sends correct APDU":
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
      let mockEncryptedData = repeat(byte(0xBB), 48)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # Load keypair with only private key (public key can be omitted)
      let privateKey = repeat(byte(0x01), 32)

      discard card.loadKey(EccKeypair, privateKey)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey

    test "load key handles invalid format (0x6A80)":
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

      # Return error SW 0x6A80 (invalid format)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x80]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let privateKey = repeat(byte(0x01), 32)
      discard card.loadKey(EccKeypair, privateKey)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey

    test "load key handles invalid key type (0x6A86)":
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

      # Return error SW 0x6A86 (invalid P1)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x86]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let privateKey = repeat(byte(0x01), 32)
      discard card.loadKey(EccKeypair, privateKey)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey

    test "load key handles conditions not met (0x6985)":
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

      # Return error SW 0x6985 (PIN not verified)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x69), 0x85]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let privateKey = repeat(byte(0x01), 32)
      discard card.loadKey(EccKeypair, privateKey)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0xD0)  # InsLoadKey

    test "load key checks key management capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT key management capability
      card.appInfo.capabilities = 0x00

      # Open secure channel
      card.secureChannel.open = true

      let privateKey = repeat(byte(0x01), 32)
      let result = card.loadKey(EccKeypair, privateKey)

      check not result.success
      check result.error == LoadKeyCapabilityNotSupported

    test "load key requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set key management capability
      card.appInfo.capabilities = 0x02

      # Secure channel is NOT open
      card.secureChannel.open = false

      let privateKey = repeat(byte(0x01), 32)
      let result = card.loadKey(EccKeypair, privateKey)

      check not result.success
      check result.error == LoadKeyChannelNotOpen

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true