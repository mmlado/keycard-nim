# Package

version       = "0.1.0"
author        = "mmlado"
description   = "nim SDK to interact with the Status Keycard"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.14"
requires "pcsc"

task test, "Run unit tests with mock PC/SC":
  exec "nim r -d:mockPcsc --path:src tests/transport_test.nim"