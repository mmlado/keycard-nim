# tests/init_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/init_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/init
import keycard/constants
import keycard/crypto/utils

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "INIT command":
  when defined(mockPcsc):
    test "init sends correct APDU structure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to pre-initialized state (has valid public key)
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Mock success response
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x90), 0x00]])

      let result = card.init("123456", "123456789012", "pairing_password")

      # Verify INIT APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0xFE (InsInit), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xFE)  # InsInit
      check tx[0][2] == byte(0x00)  # P1
      check tx[0][3] == byte(0x00)  # P2

      # Data format: length byte + public key (65) + IV (16) + ciphertext
      # Total data should be: 1 + 65 + 16 + ciphertext
      let dataLen = int(tx[0][4])
      check dataLen > 0
      check tx[0].len == 5 + dataLen  # Header + data

      # Verify result
      check result.success

    test "init succeeds with valid credentials":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set card to pre-initialized state (has valid public key)
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Mock success response
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x90), 0x00]])

      let result = card.init("123456", "123456789012", "pairing_password")

      check result.success

    test "init fails when card not selected":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Don't set publicKey - card not selected

      let result = card.init("123456", "123456789012", "pairing_password")

      check not result.success
      check result.error == InitNotSelected

    test "init fails with invalid PIN length":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # PIN too short (5 digits instead of 6)
      let result1 = card.init("12345", "123456789012", "pairing_password")
      check not result1.success
      check result1.error == InitInvalidData

      # PIN too long (7 digits instead of 6)
      let result2 = card.init("1234567", "123456789012", "pairing_password")
      check not result2.success
      check result2.error == InitInvalidData

    test "init fails with invalid PUK length":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # PUK too short (11 digits instead of 12)
      let result1 = card.init("123456", "12345678901", "pairing_password")
      check not result1.success
      check result1.error == InitInvalidData

      # PUK too long (13 digits instead of 12)
      let result2 = card.init("123456", "1234567890123", "pairing_password")
      check not result2.success
      check result2.error == InitInvalidData

    test "init handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set card to pre-initialized state
      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      let result = card.init("123456", "123456789012", "pairing_password")

      check not result.success
      check result.error == InitTransportError

    test "init handles already initialized error":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6D00 (already initialized)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6D), 0x00]])

      let result = card.init("123456", "123456789012", "pairing_password")

      check not result.success
      check result.error == InitAlreadyInitialized
      check result.sw == 0x6D00'u16

    test "init handles invalid data error from card":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6A80 (invalid data)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x80]])

      let result = card.init("123456", "123456789012", "pairing_password")

      check not result.success
      check result.error == InitInvalidData
      check result.sw == 0x6A80'u16

    test "init handles generic failed status":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      let (_, validPublicKey) = generateEcdhKeypair()
      card.publicKey = validPublicKey

      # Return error SW 0x6F00 (generic error)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6F), 0x00]])

      let result = card.init("123456", "123456789012", "pairing_password")

      check not result.success
      check result.error == InitFailed
      check result.sw == 0x6F00'u16

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
