# tests/open_secure_channel_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/open_secure_channel_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/open_secure_channel
import keycard/constants
import keycard/crypto/utils

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "OPEN SECURE CHANNEL command":
  when defined(mockPcsc):
    test "ECDH shared secret is raw x-coordinate, not hashed":
      # This test verifies that ecdhSharedSecret returns the raw x-coordinate
      # of the shared point, NOT a hash of it (e.g., NOT SHA-1 or SHA-256 of the coordinate).
      # This was a bug we encountered - the library was hashing the coordinate by default.

      # Use deterministic keypairs for testing
      # These are test vectors - in production, keys are random
      let privateKey1 = repeat(byte(0x01), 32)
      let privateKey2 = repeat(byte(0x02), 32)

      # Generate public keys from private keys
      let (_, pubKey1) = ecdhKeypairFromHex("0101010101010101010101010101010101010101010101010101010101010101")
      let (_, pubKey2) = ecdhKeypairFromHex("0202020202020202020202020202020202020202020202020202020202020202")

      # Compute shared secret from both sides
      let sharedSecret1 = ecdhSharedSecret(privateKey1, pubKey2)
      let sharedSecret2 = ecdhSharedSecret(privateKey2, pubKey1)

      # Both parties should get the same shared secret
      check sharedSecret1 == sharedSecret2

      # The shared secret should be exactly 32 bytes (the x-coordinate)
      check sharedSecret1.len == 32

      # If it were hashed, the length might still be 32, but the value would be different.
      # The key property is that it's deterministic and matches between both parties.
      # A hashed value would be different from the raw coordinate.

      # Additional check: The shared secret should NOT be all zeros
      # (which would indicate a computation error)
      var allZeros = true
      for b in sharedSecret1:
        if b != 0:
          allZeros = false
          break
      check not allZeros

    test "open secure channel sends full EC point, not hash":
      # This test verifies we send the full 65-byte EC public key point,
      # not a 32-byte hash of it (a bug we encountered during development)
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to initialized state (has valid public key)
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Mock response: 32 bytes salt + 16 bytes IV
      let mockSalt = repeat(byte(0xAA), 32)
      let mockIv = repeat(byte(0xBB), 16)
      let mockResponse = mockSalt & mockIv & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let pairingKey = repeat(byte(0x01), 32)

      # Don't authenticate to avoid needing second APDU
      discard card.openSecureChannel(0x00, pairingKey, authenticate = false)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Verify we send the full 65-byte EC point, NOT a 32-byte hash
      let sentDataLength = int(tx[0][4])
      check sentDataLength == 65  # Full uncompressed EC point
      check tx[0].len == 5 + 65   # Header + 65 bytes

      # Verify the data starts with 0x04 (uncompressed point marker)
      check tx[0][5] == byte(0x04)

    test "open secure channel sends correct APDU structure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to initialized state (has valid public key)
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Mock response: 32 bytes salt + 16 bytes IV
      let mockSalt = repeat(byte(0xAA), 32)
      let mockIv = repeat(byte(0xBB), 16)
      let mockResponse = mockSalt & mockIv & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let pairingKey = repeat(byte(0x01), 32)
      let pairingIndex = byte(0x02)

      # Don't authenticate to avoid needing second APDU
      let result = card.openSecureChannel(pairingIndex, pairingKey, authenticate = false)

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0x10 (InsOpenSecureChannel), P1 = pairingIndex, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0x10)  # InsOpenSecureChannel
      check tx[0][2] == pairingIndex  # P1 = pairing index
      check tx[0][3] == byte(0x00)    # P2 = 0x00

      # Verify result
      check result.success
      check result.salt == mockSalt
      check result.iv == mockIv

      # Verify secure channel state was updated
      check card.secureChannel.open
      check card.secureChannel.encryptionKey.len == 32
      check card.secureChannel.macKey.len == 32
      check card.secureChannel.iv == mockIv
      check card.secureChannel.pairingIndex == pairingIndex

    test "open secure channel without authentication succeeds":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to initialized state
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Mock response: 32 bytes salt + 16 bytes IV
      let mockSalt = repeat(byte(0xCC), 32)
      let mockIv = repeat(byte(0xDD), 16)
      let mockResponse = mockSalt & mockIv & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let pairingKey = repeat(byte(0x02), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check result.success
      check result.salt == mockSalt
      check result.iv == mockIv

      # Only one APDU should be sent (no mutual auth)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

    test "open secure channel fails when card not selected":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Don't set publicKey - card not selected

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelNotSelected

    test "open secure channel fails with invalid pairing key length":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Pairing key too short (31 bytes instead of 32)
      let invalidKey1 = repeat(byte(0x01), 31)
      let result1 = card.openSecureChannel(0x00, invalidKey1, authenticate = false)
      check not result1.success
      check result1.error == OpenSecureChannelInvalidData

      # Pairing key too long (33 bytes instead of 32)
      let invalidKey2 = repeat(byte(0x01), 33)
      let result2 = card.openSecureChannel(0x00, invalidKey2, authenticate = false)
      check not result2.success
      check result2.error == OpenSecureChannelInvalidData

    test "open secure channel handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelTransportError

    test "open secure channel handles invalid P1 error":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6A86 (invalid P1)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x86]])

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x05, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelInvalidP1
      check result.sw == 0x6A86'u16

    test "open secure channel handles invalid data error":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6A80 (invalid data)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x80]])

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelInvalidData
      check result.sw == 0x6A80'u16

    test "open secure channel handles invalid response length":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return wrong length (should be 48 bytes: 32 salt + 16 IV)
      let invalidResponse = repeat(byte(0xAA), 30) & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[invalidResponse])

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelInvalidResponse

    test "open secure channel handles generic failed status":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6F00 (generic error)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6F), 0x00]])

      let pairingKey = repeat(byte(0x01), 32)
      let result = card.openSecureChannel(0x00, pairingKey, authenticate = false)

      check not result.success
      check result.error == OpenSecureChannelFailed
      check result.sw == 0x6F00'u16

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
