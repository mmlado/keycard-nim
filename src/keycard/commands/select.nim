## SELECT command implementation
## Selects the Keycard applet on the card

import ../keycard
import ../constants
import ../apdu
import ../transport
import ../types/application_info

export application_info

type
  SelectError* = enum
    SelectOk
    SelectTransportError
    SelectFailed
    SelectInvalidResponse

  SelectResult* = object
    case success*: bool
    of true:
      info*: ApplicationInfo
    of false:
      error*: SelectError
      sw*: uint16

proc select*(card: var Keycard): SelectResult =
  ## Send SELECT command to select the Keycard applet
  ## 
  ## Returns a SelectResult with parsed ApplicationInfo or an error
  ## 

  let transportResult = card.transport.send(
    ins = InsSelect,
    cla = ClaIso7816,
    p1 = 0x04,
    data = KeycardAid
  )
  
  if not transportResult.success:
    return SelectResult(success: false, error: SelectTransportError, sw: 0)
  
  let resp = transportResult.value
  
  if resp.sw != SwSuccess:
    return SelectResult(success: false, error: SelectFailed, sw: resp.sw)
  
  # Parse the response and store in card state
  let appInfo = parseApplicationInfo(resp.data)
  card.publicKey = appInfo.publicKey
  card.appInfo = appInfo
  
  SelectResult(success: true, info: appInfo)