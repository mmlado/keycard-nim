# Run with: nim r -d:mockPcsc --path:src tests/get_data_test.nim

import std/unittest
import std/sequtils
import keycard/transport
import keycard/keycard
import keycard/commands/get_data
import keycard/commands/store_data
import keycard/constants

when defined(mockPcsc):
  import keycard/pcsc_shim

suite "GET DATA command":
  when defined(mockPcsc):
    test "get data sends correct APDU for public data (P1=0x00)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Mock response with some data
      let mockData: seq[byte] = @[byte(0x48), 0x65, 0x6C, 0x6C, 0x6F]  # "Hello"
      let mockResponse = mockData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getData(PublicData)

      # Verify APDU was sent correctly
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1

      # CLA = 0x80, INS = 0xCA (InsGetData), P1 = 0x00, P2 = 0x00
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xCA)  # InsGetData
      check tx[0][2] == byte(0x00)  # P1 = 0x00 (PublicData)
      check tx[0][3] == byte(0x00)  # P2

      # Check result
      check result.success
      check result.data.len == 5
      check result.data == mockData

    test "get data sends correct APDU for NDEF data (P1=0x01)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set NDEF capability (required for NDEF data)
      card.appInfo.capabilities = 0x08  # NDEF capability bit

      # Mock response
      let mockData: seq[byte] = @[byte(0xD1), 0x01, 0x02]
      let mockResponse = mockData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getData(NdefData)

      # Verify P1 = 0x01
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xCA)  # InsGetData
      check tx[0][2] == byte(0x01)  # P1 = 0x01 (NdefData)
      check tx[0][3] == byte(0x00)  # P2

      check result.success

    test "get data sends correct APDU for Cash data (P1=0x02)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Mock response
      let mockData: seq[byte] = @[byte(0x00), 0x00, 0x10, 0x00]
      let mockResponse = mockData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getData(CashData)

      # Verify P1 = 0x02
      let tx = t.mockCard().mockTxLog()
      check tx.len == 1
      check tx[0][0] == byte(0x80)
      check tx[0][1] == byte(0xCA)  # InsGetData
      check tx[0][2] == byte(0x02)  # P1 = 0x02 (CashData)
      check tx[0][3] == byte(0x00)  # P2

      check result.success

    test "get data returns empty data when nothing stored":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Mock empty response
      let mockResponse: seq[byte] = @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getData(PublicData)

      check result.success
      check result.data.len == 0

    test "get data handles undefined P1 (0x6A86)":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Return error SW 0x6A86 (undefined P1)
      t.mockCard().mockSetScriptedResponses(@[@[byte(0x6A), 0x86]])

      let result = card.getData(PublicData)

      check not result.success
      check result.error == GetDataUndefinedP1
      check result.sw == 0x6A86'u16

    test "get data handles transport error":
      let t = newTransport()
      var card = newKeycard(t)
      # Don't connect - should get transport error

      let result = card.getData(PublicData)

      check not result.success
      check result.error == GetDataTransportError

    test "get data checks NDEF capability for NDEF data":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Set app info WITHOUT NDEF capability
      card.appInfo.capabilities = 0x00  # No NDEF capability

      let result = card.getData(NdefData)

      check not result.success
      check result.error == GetDataCapabilityNotSupported

    test "get data does not require secure channel":
      let t = newTransport()
      var card = newKeycard(t)
      defer: card.close()
      card.connect("Mock Reader A")

      # Secure channel is NOT open
      card.secureChannel.open = false

      # Mock response
      let mockData: seq[byte] = @[byte(0x01), 0x02, 0x03]
      let mockResponse = mockData & @[byte(0x90), 0x00]
      t.mockCard().mockSetScriptedResponses(@[mockResponse])

      let result = card.getData(PublicData)

      # Should succeed without secure channel
      check result.success
      check result.data == mockData

when not defined(mockPcsc):
  suite "Mock tests skipped":
    test "run with -d:mockPcsc to enable":
      check true
