# tests/transport_test.nim
# Run with: nim r -d:mockPcsc tests/transport_test.nim
# (or use testament; the important part is -d:mockPcsc so the shim uses the mock)

import std/unittest
import keycard/transport
import keycard/pcsc_shim
import strutils

suite "Transport with mocked PC/SC":
  when defined(mockPcsc):
    test "listReaders returns mock readers":
      let tr = newTransport()
      defer: tr.close()
      let rs = tr.listReaders()
      check rs.len == 2
      check "Mock Reader A" in rs

    test "connect + transmit parses SW and data":
      let tr = newTransport()
      defer: tr.close()
      tr.connect("Mock Reader A")

      tr.mockCard().mockSetScriptedResponses(@[
        @[byte 0x11, 0x22, 0x90, 0x00],
        @[byte 0x6A, 0x82]
      ])

      let r1 = tr.transmitHex("00 A4 04 00")
      check r1.data == @[byte 0x11, 0x22]
      check r1.sw == 0x9000'u16

      let r2 = tr.transmit(@[byte 0x00, 0xB0, 0x00, 0x00, 0x00])
      check r2.data.len == 0
      check r2.sw == 0x6A82'u16

      let tx = tr.mockCard().mockTxLog()
      check tx.len == 2

    test "short response raises":
      let tr = newTransport()
      defer: tr.close()
      tr.connect("Mock Reader B")
      tr.mockCard().mockSetScriptedResponses(@[@[byte 0x90]])
      expect IOError:
        discard tr.transmitHex("80 CA 9F 7F 00")

    test "transmitExpectOk returns data or raises on SW != 9000":
      let tr = newTransport()
      defer: tr.close()
      tr.connect("Mock Reader A")
      tr.mockCard().mockSetScriptedResponses(@[
        @[byte 0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00], # OK
        @[byte 0x6A, 0x82]                          # error
      ])

      let data = tr.transmitExpectOk(@[byte 0x00, 0xA4, 0x04, 0x00])
      check data == @[byte 0xDE, 0xAD, 0xBE, 0xEF]

      expect IOError:
        discard tr.transmitExpectOk(@[byte 0x00])

    test "pretty `$` includes hex SW":
      let tr = newTransport()
      defer: tr.close()
      tr.connect("Mock Reader A")
      tr.mockCard().mockSetScriptedResponses(@[
        @[byte 0x99, 0x90, 0x00]
      ])
      let r = tr.transmit(@[byte 0x00])
      let s = $r
      check "sw=9000" in s
      check "99" in s
  else:
    test "mock-only tests skipped (run with -d:mockPcsc)":
      check true