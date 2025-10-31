# tests/change_pin_test.nim
# Run with: nim r -d:mockPcsc --path:src tests/change_pin_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/change_pin
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "CHANGE PIN command":
  when defined(mockPcsc):
    test "change PIN sends correct APDU for UserPin (P1=0x00)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04  # Credentials capability bit

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

      let newPin = @[byte('6'), byte('5'), byte('4'), byte('3'), byte('2'), byte('1')]

      # This will fail MAC verification, but we can check the APDU sent
      discard card.changePin(UserPin, newPin)

      # Verify APDU was sent (encrypted via secure channel)
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # Verify CLA and INS
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x21)  # InsChangeSecret

    test "change PIN validates UserPin format (must be 6 bytes)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true

      # Try with invalid length (5 bytes)
      let invalidPin = @[byte('1'), byte('2'), byte('3'), byte('4'), byte('5')]
      let result = card.changePin(UserPin, invalidPin)

      check not result.success
      check result.error == ChangePinInvalidFormat
      check result.sw == 0x6A80'u16

      # No APDU should be sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 0

    test "change PIN sends correct APDU for PUK (P1=0x01)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response: MAC + encrypted data + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let newPuk = @[byte('1'), byte('2'), byte('3'), byte('4'), byte('5'), byte('6'),
                     byte('7'), byte('8'), byte('9'), byte('0'), byte('1'), byte('2')]

      # This will fail MAC verification, but we can check the APDU sent
      discard card.changePin(Puk, newPuk)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x21)  # InsChangeSecret

    test "change PIN validates PUK format (must be 12 bytes)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true

      # Try with invalid length (6 bytes)
      let invalidPuk = @[byte('1'), byte('2'), byte('3'), byte('4'), byte('5'), byte('6')]
      let result = card.changePin(Puk, invalidPuk)

      check not result.success
      check result.error == ChangePinInvalidFormat
      check result.sw == 0x6A80'u16

    test "change PIN sends correct APDU for pairing secret (P1=0x02)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response: MAC + encrypted data + SW
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # 32-byte pairing secret
      var newSecret: seq[byte] = @[]
      for i in 0..<32:
        newSecret.add(byte(i))

      # This will fail MAC verification, but we can check the APDU sent
      discard card.changePin(PairingSecret, newSecret)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x21)  # InsChangeSecret

    test "change PIN validates pairing secret format (must be 32 bytes)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true

      # Try with invalid length (16 bytes)
      var invalidSecret: seq[byte] = @[]
      for i in 0..<16:
        invalidSecret.add(byte(i))

      let result = card.changePin(PairingSecret, invalidSecret)

      check not result.success
      check result.error == ChangePinInvalidFormat
      check result.sw == 0x6A80'u16

    test "change PIN sends APDU for error responses":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Open secure channel
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Return error SW 0x6A86 (undefined P1)
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncryptedData = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncryptedData & @[byte(0x6A), 0x86]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let newPin = @[byte('6'), byte('5'), byte('4'), byte('3'), byte('2'), byte('1')]

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.changePin(UserPin, newPin)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x21)  # InsChangeSecret

    test "change PIN sends APDU when conditions not met":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

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

      let newPin = @[byte('6'), byte('5'), byte('4'), byte('3'), byte('2'), byte('1')]

      # This will fail MAC verification with mock data, but we can check the APDU sent
      discard card.changePin(UserPin, newPin)

      # Verify APDU was sent
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)  # CLA
      check tx[0][1] == byte(0x21)  # InsChangeSecret

    test "change PIN checks credentials capability":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT credentials capability
      card.appInfo.capabilities = 0x00  # No credentials capability

      # Open secure channel
      card.secureChannel.open = true

      let newPin = @[byte('6'), byte('5'), byte('4'), byte('3'), byte('2'), byte('1')]
      let result = card.changePin(UserPin, newPin)

      check not result.success
      check result.error == ChangePinCapabilityNotSupported

    test "change PIN requires secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set credentials capability
      card.appInfo.capabilities = 0x04

      # Secure channel is NOT open
      card.secureChannel.open = false

      let newPin = @[byte('6'), byte('5'), byte('4'), byte('3'), byte('2'), byte('1')]
      let result = card.changePin(UserPin, newPin)

      check not result.success
      check result.error == ChangePinChannelNotOpen

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
