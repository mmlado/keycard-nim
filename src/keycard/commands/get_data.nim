## GET DATA command implementation
## Retrieves public data, NDEF data, or Cash data

import ../keycard
import ../constants
import ../transport
import ./store_data

export DataType

type
  GetDataError* = enum
    GetDataOk
    GetDataTransportError
    GetDataUndefinedP1          # SW 0x6A86
    GetDataFailed
    GetDataCapabilityNotSupported  # NDEF capability required for NdefData

  GetDataResult* = object
    case success*: bool
    of true:
      data*: seq[byte]
    of false:
      error*: GetDataError
      sw*: uint16

proc getData*(card: var Keycard; dataType: DataType): GetDataResult =
  ## Get data from the card
  ##
  ## Args:
  ##   dataType: Type of data to retrieve (PublicData, NdefData, or CashData)
  ##
  ## This command does NOT require secure channel or PIN verification.
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A86 on undefined P1
  ##
  ## Response Data:
  ##   The data as previously stored by STORE DATA

  if dataType == NdefData and not card.appInfo.hasNdef():
    return GetDataResult(success: false,
                        error: GetDataCapabilityNotSupported,
                        sw: 0)

  let transportResult = card.transport.send(
    ins = InsGetData,
    cla = ClaProprietary,
    p1 = byte(dataType),
    p2 = 0x00
  )

  if not transportResult.success:
    return GetDataResult(success: false,
                        error: GetDataTransportError,
                        sw: 0)

  let resp = transportResult.value

  case resp.sw
  of SwSuccess:
    return GetDataResult(success: true, data: resp.data)
  of 0x6A86:
    return GetDataResult(success: false,
                        error: GetDataUndefinedP1,
                        sw: resp.sw)
  else:
    return GetDataResult(success: false,
                        error: GetDataFailed,
                        sw: resp.sw)