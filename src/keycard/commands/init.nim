## INIT command implementation
## Initialize the Keycard with PIN, PUK, and pairing secret

import ../keycard
import ../constants
import ../apdu
import ../transport
import ../crypto/utils
import ../util

type
  InitError* = enum
    InitOk
    InitTransportError
    InitAlreadyInitialized
    InitInvalidData
    InitFailed
    InitNotSelected

  InitResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: InitError
      sw*: uint16

proc init*(card: var Keycard; 
           pin: string;
           puk: string; 
           pairingSecret: string): InitResult =
  ## Initialize the Keycard with security credentials
  ## 
  ## Args:
  ##   pin: 6-digit PIN code
  ##   puk: 12-digit PUK code
  ##   pairingSecret: Pairing password (will be converted to 32-byte secret)
  ## 
  ## The card must be in pre-initialized state (after SELECT).
  ## Uses ECDH with the card's public key to encrypt the credentials.
  ## 
  ## APDU format:
  ##   CLA = 0x80
  ##   INS = 0xFE
  ##   P1 = 0x00
  ##   P2 = 0x00
  ##   Data = EC public key (LV) | IV | encrypted payload
  
  if card.publicKey.len == 0:
    return InitResult(success: false, error: InitNotSelected, sw: 0)
  
  if pin.len != PinLength:
    return InitResult(success: false, error: InitInvalidData, sw: 0)
  if puk.len != PukLength:
    return InitResult(success: false, error: InitInvalidData, sw: 0)
  
  var pinBytes = stringToBytes(pin)
  var pukBytes = stringToBytes(puk)
  
  let pairingBytes = generatePairingToken(pairingSecret)
  
  let (ephemeralPrivate, ephemeralPublic) = generateEcdhKeypair()
  
  let sharedSecret = ecdhSharedSecret(ephemeralPrivate, card.publicKey)
  
  let iv = generateRandomBytes(16)
  
  var payload: seq[byte] = @[]
  payload.add(pinBytes)
  payload.add(pukBytes)
  payload.add(pairingBytes)
  
  let ciphertext = aesCbcEncrypt(sharedSecret, iv, payload)
  
  var data: seq[byte] = @[]
  data.add(byte(ephemeralPublic.len))
  data.add(ephemeralPublic)
  data.add(iv)
  data.add(ciphertext)
  
  if data.len > 255:
    return InitResult(success: false, error: InitInvalidData, sw: 0)
  
  let transportResult = card.transport.send(
    ins = InsInit,
    data = data
  )
  
  if not transportResult.success:
    return InitResult(success: false, error: InitTransportError, sw: 0)
  
  let resp = transportResult.value
  
  case resp.sw
  of SwSuccess:
    return InitResult(success: true)
  of SwInsNotSupported:
    return InitResult(success: false, error: InitAlreadyInitialized, sw: resp.sw)
  of SwWrongData:
    return InitResult(success: false, error: InitInvalidData, sw: resp.sw)
  else:
    return InitResult(success: false, error: InitFailed, sw: resp.sw)