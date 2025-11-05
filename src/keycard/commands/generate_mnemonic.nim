## GENERATE MNEMONIC command implementation
## Generates a BIP39 mnemonic as a sequence of word indexes

import ../keycard
import ../constants
import ../secure_apdu

type
  GenerateMnemonicError* = enum
    GenerateMnemonicOk
    GenerateMnemonicTransportError
    GenerateMnemonicInvalidChecksumSize  # SW 0x6A86
    GenerateMnemonicFailed
    GenerateMnemonicCapabilityNotSupported
    GenerateMnemonicSecureApduError
    GenerateMnemonicChannelNotOpen

  GenerateMnemonicResult* = object
    case success*: bool
    of true:
      indexes*: seq[uint16]  # Word indexes (0-2047) for BIP39 wordlist
    of false:
      error*: GenerateMnemonicError
      sw*: uint16

proc parseWordIndexes*(data: seq[byte]): seq[uint16] =
  ## Parse response data as a sequence of 16-bit integers (MSB first)
  ## Each word index is 2 bytes: high byte, low byte
  result = @[]
  var pos = 0

  while pos + 1 < data.len:
    let highByte = uint16(data[pos])
    let lowByte = uint16(data[pos + 1])
    let wordIndex = (highByte shl 8) or lowByte
    result.add(wordIndex)
    pos += 2

proc generateMnemonic*(
  card: var Keycard;
  checksumSize: int = 4
): GenerateMnemonicResult =
  ## Generate a BIP39 mnemonic as a sequence of word indexes
  ##
  ## Args:
  ##   checksumSize: Size of checksum in bits (4-8, default 4)
  ##                 - 4 bits = 12 words (128 bits entropy)
  ##                 - 8 bits = 24 words (256 bits entropy)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - Key management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A86 if P1 (checksum size) is invalid
  ##
  ## Response Data:
  ##   Sequence of 16-bit integers (MSB first)
  ##   Each integer is a word index (0-2047) for BIP39 wordlist
  ##
  ## Notes:
  ##   - Checksum size determines mnemonic length:
  ##     - 4 bits → 12 words
  ##     - 5 bits → 15 words
  ##     - 6 bits → 18 words
  ##     - 7 bits → 21 words
  ##     - 8 bits → 24 words

  if not card.appInfo.hasKeyManagement():
    return GenerateMnemonicResult(success: false,
                                  error: GenerateMnemonicCapabilityNotSupported,
                                  sw: 0)

  if not card.secureChannel.open:
    return GenerateMnemonicResult(success: false,
                                  error: GenerateMnemonicChannelNotOpen,
                                  sw: 0)

  if checksumSize < 4 or checksumSize > 8:
    return GenerateMnemonicResult(success: false,
                                  error: GenerateMnemonicInvalidChecksumSize,
                                  sw: 0x6A86)

  let secureResult = card.sendSecure(
    ins = InsGenerateMnemonic,
    p1 = byte(checksumSize)
  )

  if not secureResult.success:
    let mnemonicError = case secureResult.error
      of SecureApduChannelNotOpen:
        GenerateMnemonicChannelNotOpen
      of SecureApduTransportError:
        GenerateMnemonicTransportError
      of SecureApduInvalidMac:
        GenerateMnemonicSecureApduError
      else:
        GenerateMnemonicSecureApduError

    return GenerateMnemonicResult(success: false,
                                  error: mnemonicError,
                                  sw: 0)

  case secureResult.sw
  of SwSuccess:
    let indexes = parseWordIndexes(secureResult.data)
    return GenerateMnemonicResult(success: true, indexes: indexes)
  of 0x6A86:
    return GenerateMnemonicResult(success: false,
                                  error: GenerateMnemonicInvalidChecksumSize,
                                  sw: secureResult.sw)
  else:
    return GenerateMnemonicResult(success: false,
                                  error: GenerateMnemonicFailed,
                                  sw: secureResult.sw)