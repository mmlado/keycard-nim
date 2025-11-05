# Package
import std/os
import std/strutils

version       = "0.1.0"
author        = "mmlado"
description   = "nim SDK to interact with the Status Keycard"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.14"
requires "pcsc"
requires "nimcrypto"
requires "https://github.com/status-im/nim-secp256k1"

task test, "Run unit tests with mock PC/SC":
  exec "nim r -d:mockPcsc --path:src tests/transport_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/select_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/reset_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/init_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/pair_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/open_secure_channel_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/mutually_authenticate_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/verify_pin_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/change_pin_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/unblock_pin_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/unpair_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/ident_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/get_status_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/store_data_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/get_data_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/generate_key_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/remove_key_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/export_key_test.nim"
  exec "nim r -d:mockPcsc --path:src tests/sign_test.nim"

task example, "Run example":
  exec "nim c -r --path:src example/example.nim"

task clean, "Clean build artifacts":
  exec "rm -rf nimcache/"
  exec "rm -rf tests/nimcache/"
  exec "rm -rf examples/nimcache/"
  # Remove compiled binaries
  exec "rm -f tests/transport_test"
  exec "rm -f tests/select_test"
  exec "rm -f examples/example"