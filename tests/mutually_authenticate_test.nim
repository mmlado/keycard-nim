# tests/mutually_authenticate_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/mutually_authenticate_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/mutually_authenticate
import keycard/constants
import keycard/crypto/utils

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "MUTUALLY AUTHENTICATE command":
  when defined(mockPcsc):
    test "mutually authenticate sends correct APDU structure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock response: MAC (16 bytes) + encrypted response (32 bytes)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedResponse = repeat(byte(0xBB), 32)
      let mockResponse = mockMac & mockEncryptedResponse & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # This will fail MAC verification, but we can check the APDU sent
      discard card.mutuallyAuthenticate()

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0x11 (InsMutuallyAuthenticate), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0x11)  # InsMutuallyAuthenticate
      check tx[0][2] == byte(0x00)  # P1
      check tx[0][3] == byte(0x00)  # P2

      # Data should be: MAC (16 bytes) + encrypted challenge (48 bytes with padding)
      let dataLen = int(tx[0][4])
      check dataLen >= 16  # At least MAC length
      check tx[0].len == 5 + dataLen  # Header + data

    test "mutually authenticate updates IV with sent MAC":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      let initialIv = repeat(byte(0x03), 16)
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = initialIv

      # Mock response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedResponse = repeat(byte(0xBB), 32)
      let mockResponse = mockMac & mockEncryptedResponse & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      discard card.mutuallyAuthenticate()

      # IV should have been updated with the MAC that was sent
      # (even though MAC verification will fail, the IV is updated before sending)
      check card.secureChannel.iv != initialIv
      check card.secureChannel.iv.len == 16

    test "mutually authenticate fails when secure channel not open":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateChannelNotOpen

    test "mutually authenticate handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateTransportError
      # Secure channel should be closed on error
      check not card.secureChannel.open

    test "mutually authenticate handles authentication failed (0x6982)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6982 (authentication failed)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x69), 0x82]])

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateFailed
      check result.sw == SwSecurityStatusNotSatisfied
      # Secure channel should be closed on error
      check not card.secureChannel.open

    test "mutually authenticate handles not after open secure channel (0x6985)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6985 (not after open secure channel)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x69), 0x85]])

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateNotAfterOpen
      check result.sw == SwConditionsNotSatisfied
      # Secure channel should be closed on error
      check not card.secureChannel.open

    test "mutually authenticate handles generic failure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6F00 (generic error)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6F), 0x00]])

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateFailed
      check result.sw == 0x6F00'u16
      # Secure channel should be closed on error
      check not card.secureChannel.open

    test "mutually authenticate handles invalid response length":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return response that's too short (less than 16 bytes)
      let invalidResponse = repeat(byte(0xAA), 10) & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[invalidResponse])

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateInvalidResponse
      # Secure channel should be closed on error
      check not card.secureChannel.open

    test "mutually authenticate handles MAC verification failure":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return response with invalid MAC (won't match calculated MAC)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedResponse = repeat(byte(0xBB), 32)
      let mockResponse = mockMac & mockEncryptedResponse & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.mutuallyAuthenticate()

      check not result.success
      check result.error == MutuallyAuthenticateMacVerifyFailed
      # Secure channel should be closed on error
      check not card.secureChannel.open

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true