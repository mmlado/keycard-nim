## SET PINLESS PATH command implementation
## Sets a path that allows signing without PIN verification

import ../keycard
import ../constants
import ../secure_apdu
import strutils

type
  DerivationSource* = enum
    Master = 0      # Master key "m"
    Parent = 1      # Parent key ".."
    Current = 2     # Current key "."

  SetPinlessPathError* = enum
    SetPinlessPathOk
    SetPinlessPathTransportError
    SetPinlessPathInvalidData
    SetPinlessPathFailed
    SetPinlessPathCapabilityNotSupported
    SetPinlessPathSecureApduError
    SetPinlessPathChannelNotOpen
    SetPinlessPathConditionsNotMet # PIN not verified

  SetPinlessPathResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: SetPinlessPathError
      sw*: uint16

  KeyPath* = object
    ## Represents a BIP-32 derivation path
    source*: DerivationSource
    components*: seq[uint32]

const
  MaxPathComponents = 10
  HardenedBit = 0x8000_0000'u32

proc isAllDigits(s: string): bool =
  ## Check if all characters in string are digits
  if s.len == 0:
    return false
  for c in s:
    if c < '0' or c > '9':
      return false
  return true

proc parsePathComponent(token: string): uint32 =
  ## Parse a single path component (e.g., "44'" or "0")
  ## Returns the component value with hardened bit set if applicable
  var value: uint32
  var hardened = false

  if token.endsWith("'"):
    hardened = true
    let numPart = token[0 .. ^2]
    if not isAllDigits(numPart):
      raise newException(ValueError, "Invalid component: " & token)
    value = parseUInt(numPart).uint32
  else:
    if not isAllDigits(token):
      raise newException(ValueError, "Invalid component: " & token)
    value = parseUInt(token).uint32

  if hardened:
    value = value or HardenedBit

  return value

proc parsePath*(path: string): KeyPath =
  ## Parse a BIP-32 path string into a KeyPath object
  ##
  ## Supports formats:
  ##   - "m/44'/60'/0'/0/0" (master key)
  ##   - "../0/1" (parent key)
  ##   - "./0" or "0" (current key)
  ##   - "" (empty path - disables PIN-less path)
  ##
  ## Raises ValueError if the path is invalid

  if path == "":
    # Empty path - return empty components to disable PIN-less path
    return KeyPath(source: Current, components: @[])

  let tokens = path.split('/')
  if tokens.len == 0:
    raise newException(ValueError, "Empty path")

  var source: DerivationSource
  var startIdx: int

  case tokens[0]
  of "m":
    source = Master
    startIdx = 1
  of "..":
    source = Parent
    startIdx = 1
  of ".":
    source = Current
    startIdx = 1
  else:
    # If no prefix, assume current key
    source = Current
    startIdx = 0

  var components: seq[uint32] = @[]
  for i in startIdx ..< tokens.len:
    components.add(parsePathComponent(tokens[i]))

  if components.len > MaxPathComponents:
    raise newException(ValueError, "Too many components in derivation path")

  return KeyPath(source: source, components: components)

proc encodePath*(path: KeyPath): seq[byte] =
  ## Encode a KeyPath as a sequence of 32-bit big-endian integers
  result = newSeq[byte](path.components.len * 4)
  for i, value in path.components:
    let offset = i * 4
    result[offset] = byte((value shr 24) and 0xFF)
    result[offset + 1] = byte((value shr 16) and 0xFF)
    result[offset + 2] = byte((value shr 8) and 0xFF)
    result[offset + 3] = byte(value and 0xFF)

proc pathToString*(path: KeyPath): string =
  ## Convert a KeyPath back to string representation
  let prefix = case path.source
    of Master: "m"
    of Parent: ".."
    of Current: "."

  if path.components.len == 0:
    return ""

  var parts: seq[string] = @[prefix]
  for comp in path.components:
    if (comp and HardenedBit) != 0:
      parts.add($(comp and not HardenedBit) & "'")
    else:
      parts.add($comp)

  return parts.join("/")

proc setPinlessPath*(
  card: var Keycard;
  path: string
): SetPinlessPathResult =
  ## Set a PIN-less path on the card
  ##
  ## When the current derived key matches this path, SIGN will work without
  ## PIN authentication or pairing. An empty path ("") disables PIN-less signing.
  ##
  ## Args:
  ##   path: BIP-32-style path (e.g., "m/44'/60'/0'/0/0") or "" to disable
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - User PIN must be verified
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if data is invalid
  ##
  ## Raises:
  ##   ValueError if the path string is malformed

  if not card.secureChannel.open:
    return SetPinlessPathResult(success: false,
                                error: SetPinlessPathChannelNotOpen,
                                sw: 0)

  # Parse the path string
  let keyPath = try:
    parsePath(path)
  except ValueError as e:
    raise newException(ValueError, "Invalid path: " & e.msg)

  # Encode the path as binary data
  let data = encodePath(keyPath)

  let secureResult = card.sendSecure(
    ins = InsSetPinlessPath,
    data = data
  )

  if not secureResult.success:
    let pathError = case secureResult.error
      of SecureApduChannelNotOpen:
        SetPinlessPathChannelNotOpen
      of SecureApduTransportError:
        SetPinlessPathTransportError
      of SecureApduInvalidMac:
        SetPinlessPathSecureApduError
      else:
        SetPinlessPathSecureApduError

    return SetPinlessPathResult(success: false,
                               error: pathError,
                               sw: 0)

  case secureResult.sw
  of SwSuccess:
    return SetPinlessPathResult(success: true)
  of SwWrongData:
    return SetPinlessPathResult(success: false,
                               error: SetPinlessPathInvalidData,
                               sw: secureResult.sw)
  of SwConditionsNotSatisfied:
    return SetPinlessPathResult(success: false,
                               error: SetPinlessPathConditionsNotMet,
                               sw: secureResult.sw)
  else:
    return SetPinlessPathResult(success: false,
                               error: SetPinlessPathFailed,
                               sw: secureResult.sw)