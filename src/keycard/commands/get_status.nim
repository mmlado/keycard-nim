## GET STATUS command implementation
## Retrieves application status or key path

import ../keycard
import ../constants
import ../secure_apdu
import ../tlv

type
  GetStatusError* = enum
    GetStatusOk
    GetStatusTransportError
    GetStatusUndefinedP1
    GetStatusFailed
    GetStatusChannelNotOpen
    GetStatusSecureApduError
    GetStatusInvalidResponse

  ApplicationStatus* = object
    pinRetryCount*: byte
    pukRetryCount*: byte
    keyInitialized*: bool

  GetStatusResult* = object
    case success*: bool
    of true:
      case isAppStatus*: bool
      of true:
        appStatus*: ApplicationStatus
      of false:
        keyPath*: seq[uint32]    # Empty if master key selected
    of false:
      error*: GetStatusError
      sw*: uint16

proc getStatus*(card: var Keycard; getKeyPath: bool = false): GetStatusResult =
  ## Get application status or key path
  ##
  ## Args:
  ##   getKeyPath: If true, returns key path (P1=0x01), otherwise app status (P1=0x00)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##
  ## This command is sent as an encrypted/MAC'd secure APDU.
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A86 on undefined P1
  ##
  ## Response Data (P1=0x00):
  ##   Tag 0xA3 = Application Status Template
  ##     Tag 0x02 = PIN retry count (1 byte)
  ##     Tag 0x02 = PUK retry count (1 byte)
  ##     Tag 0x01 = 0xff if key initialized, 0 otherwise
  ##
  ## Response Data (P1=0x01):
  ##   Sequence of 32-bit numbers (key path)

  if not card.secureChannel.open:
    return GetStatusResult(success: false,
                          error: GetStatusChannelNotOpen,
                          sw: 0)

  let p1 = if getKeyPath: byte(0x01) else: byte(0x00)

  let secureResult = card.sendSecure(
    ins = InsGetStatus,
    p1 = p1
  )

  if not secureResult.success:
    let statusError = case secureResult.error
      of SecureApduChannelNotOpen:
        GetStatusChannelNotOpen
      of SecureApduTransportError:
        GetStatusTransportError
      of SecureApduInvalidMac:
        GetStatusSecureApduError
      else:
        GetStatusSecureApduError

    return GetStatusResult(success: false,
                          error: statusError,
                          sw: 0)

  case secureResult.sw
  of SwSuccess:
    discard
  of SwIncorrectP1P2:
    return GetStatusResult(success: false,
                          error: GetStatusUndefinedP1,
                          sw: secureResult.sw)
  else:
    return GetStatusResult(success: false,
                          error: GetStatusFailed,
                          sw: secureResult.sw)

  if getKeyPath:
    var keyPath: seq[uint32] = @[]
    var pos = 0

    while pos + 4 <= secureResult.data.len:
      let value = (uint32(secureResult.data[pos]) shl 24) or
                  (uint32(secureResult.data[pos + 1]) shl 16) or
                  (uint32(secureResult.data[pos + 2]) shl 8) or
                  uint32(secureResult.data[pos + 3])
      keyPath.add(value)
      pos += 4

    return GetStatusResult(success: true,
                          isAppStatus: false,
                          keyPath: keyPath)
  else:
    let tags = parseTlv(secureResult.data)
    let statusTemplate = findTag(tags, 0xA3)

    if statusTemplate.len == 0:
      return GetStatusResult(success: false,
                            error: GetStatusInvalidResponse,
                            sw: secureResult.sw)

    let innerTags = parseTlv(statusTemplate)

    var pinRetry: byte = 0
    var pukRetry: byte = 0
    var keyInit: byte = 0
    var foundValues = 0

    for tag in innerTags:
      case tag.tag
      of 0x02:
        if foundValues == 0:
          if tag.value.len > 0:
            pinRetry = tag.value[0]
            foundValues = 1
        elif foundValues == 1:
          if tag.value.len > 0:
            pukRetry = tag.value[0]
            foundValues = 2
      of 0x01:
        if tag.value.len > 0:
          keyInit = tag.value[0]
      else:
        discard

    return GetStatusResult(success: true,
                          isAppStatus: true,
                          appStatus: ApplicationStatus(
                            pinRetryCount: pinRetry,
                            pukRetryCount: pukRetry,
                            keyInitialized: keyInit == 0xff
                          ))