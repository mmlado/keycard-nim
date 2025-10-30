# Run with: nim r -d:mockPcsc --path:src tests/store_data_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/store_data
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "STORE DATA command":
  when defined(mockPcsc):
    test "store data sends correct APDU for public data (P1=0x00)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let testData: seq[byte] = @[byte(0x48), 0x65, 0x6C, 0x6C, 0x6F]  # "Hello"
      discard card.storeData(PublicData, testData)

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0xE2 (InsStoreData), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xE2)  # InsStoreData
      check tx[0][2] == byte(0x00)  # P1 = 0x00 (PublicData)
      check tx[0][3] == byte(0x00)  # P2

    test "store data sends correct APDU for NDEF data (P1=0x01)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response
      card.appInfo.capabilities = 0x08  # NDEF capability bit
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let testData: seq[byte] = @[byte(0xD1), 0x01, 0x02, 0x54, 0x02]  # NDEF record
      discard card.storeData(NdefData, testData)

      # Verify P1 = 0x01
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xE2)  # InsStoreData
      check tx[0][2] == byte(0x01)  # P1 = 0x01 (NdefData)
      check tx[0][3] == byte(0x00)  # P2

    test "store data sends correct APDU for Cash data (P1=0x02)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let testData: seq[byte] = @[byte(0x00), 0x00, 0x10, 0x00]  # Cash value
      discard card.storeData(CashData, testData)

      # Verify P1 = 0x02
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xE2)  # InsStoreData
      check tx[0][2] == byte(0x02)  # P1 = 0x02 (CashData)
      check tx[0][3] == byte(0x00)  # P2

    test "store data with large payload":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Mock success response
      let mockMac = repeat(byte(0xAA), 16)
      let mockEncrypted = repeat(byte(0xBB), 16)
      let mockResponse = mockMac & mockEncrypted & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      # 127 bytes of data (max recommended)
      let largeData = repeat(byte(0xFF), 127)
      discard card.storeData(PublicData, largeData)

      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

    test "store data fails when secure channel not open":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      let testData: seq[byte] = @[byte(0x01), 0x02, 0x03]
      let result = card.storeData(PublicData, testData)

      check not result.success
      check result.error == StoreDataChannelNotOpen

    test "store data handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      let testData: seq[byte] = @[byte(0x01), 0x02, 0x03]
      let result = card.storeData(PublicData, testData)

      check not result.success
      check result.error == StoreDataTransportError

    test "store data checks NDEF capability for NDEF data":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set up open secure channel state
      card.secureChannel.open = true
      card.secureChannel.encryptionKey = repeat(byte(0x01), 32)
      card.secureChannel.macKey = repeat(byte(0x02), 32)
      card.secureChannel.iv = repeat(byte(0x03), 16)

      # Set app info WITHOUT NDEF capability
      card.appInfo.capabilities = 0x00  # No NDEF capability

      let testData: seq[byte] = @[byte(0xD1), 0x01, 0x02]
      let result = card.storeData(NdefData, testData)

      check not result.success
      check result.error == StoreDataCapabilityNotSupported

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
