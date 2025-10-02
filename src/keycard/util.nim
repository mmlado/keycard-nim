## Utility functions for keycard operations

import strutils

proc swHex*(sw: uint16): string =
  ## Convert status word to hex string
  ## Avoids "target type is larger than source type" warning
  toHex(uint32(sw), 4)