## STORE DATA command implementation
## Stores public data, NDEF data, or Cash data

import ../keycard
import ../constants
import ../secure_apdu

type
  DataType* = enum
    PublicData = 0x00
    NdefData = 0x01
    CashData = 0x02

  StoreDataError* = enum
    StoreDataOk
    StoreDataTransportError
    StoreDataUndefinedP1
    StoreDataTooLong
    StoreDataFailed
    StoreDataChannelNotOpen
    StoreDataSecureApduError
    StoreDataCapabilityNotSupported  # NDEF capability required for NdefData

  StoreDataResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: StoreDataError
      sw*: uint16

proc storeData*(card: var Keycard; dataType: DataType; data: seq[byte]): StoreDataResult =
  ## Store data on the card
  ##
  ## Args:
  ##   dataType: Type of data to store (PublicData, NdefData, or CashData)
  ##   data: Data to store (should be <= 127 bytes)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - User PIN must be verified
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A86 on undefined P1
  ##   0x6A80 if data is too long

  if not card.secureChannel.open:
    return StoreDataResult(success: false,
                          error: StoreDataChannelNotOpen,
                          sw: 0)

  if dataType == NdefData and not card.appInfo.hasNdef():
    return StoreDataResult(success: false,
                          error: StoreDataCapabilityNotSupported,
                          sw: 0)

  let secureResult = card.sendSecure(
    ins = InsStoreData,
    p1 = byte(dataType),
    data = data
  )

  if not secureResult.success:
    let storeError = case secureResult.error
      of SecureApduChannelNotOpen:
        StoreDataChannelNotOpen
      of SecureApduTransportError:
        StoreDataTransportError
      of SecureApduInvalidMac:
        StoreDataSecureApduError
      else:
        StoreDataSecureApduError

    return StoreDataResult(success: false,
                          error: storeError,
                          sw: 0)

  case secureResult.sw
  of SwSuccess:
    return StoreDataResult(success: true)
  of SwIncorrectP1P2:
    return StoreDataResult(success: false,
                          error: StoreDataUndefinedP1,
                          sw: secureResult.sw)
  of SwWrongData:
    return StoreDataResult(success: false,
                          error: StoreDataTooLong,
                          sw: secureResult.sw)
  else:
    return StoreDataResult(success: false,
                          error: StoreDataFailed,
                          sw: secureResult.sw)