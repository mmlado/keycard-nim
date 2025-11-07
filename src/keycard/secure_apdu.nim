## Secure APDU encryption and decryption
## Handles encrypted communication over secure channel

import keycard
import transport
import apdu
import crypto/utils
import constants

export ApduResponse

type
  SecureApduError* = enum
    SecureApduOk
    SecureApduChannelNotOpen
    SecureApduInvalidMac
    SecureApduTransportError

  SecureApduResult* = object
    case success*: bool
    of true:
      data*: seq[byte]
      sw*: uint16
    of false:
      error*: SecureApduError

proc encryptApdu*(card: var Keycard;
                  cla: byte;
                  ins: byte;
                  p1: byte;
                  p2: byte;
                  data: seq[byte]): seq[byte] =
  ## Encrypt APDU data for secure channel transmission

  let encrypted = aesCbcEncrypt(card.secureChannel.encryptionKey,
                                card.secureChannel.iv,
                                data)

  var macInput: seq[byte] = @[]
  macInput.add(cla)
  macInput.add(ins)
  macInput.add(p1)
  macInput.add(p2)
  macInput.add(byte(encrypted.len + AesMacSize))

  for i in 0..<11:
    macInput.add(0x00)

  macInput.add(encrypted)

  let mac = aesCbcMac(card.secureChannel.macKey, macInput)

  card.secureChannel.iv = mac

  result = @[]
  result.add(mac)
  result.add(encrypted)

proc decryptResponse*(card: var Keycard; response: seq[byte]): SecureApduResult =
  ## Decrypt R-APDU response from secure channel

  if response.len < AesMacSize:
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  let receivedMac = response[0..<AesMacSize]
  let encryptedData = response[AesMacSize..^1]

  var macInput: seq[byte] = @[]
  macInput.add(byte(response.len))

  for i in 0..<15:
    macInput.add(0x00)

  macInput.add(encryptedData)

  let calculatedMac = aesCbcMac(card.secureChannel.macKey, macInput)

  if receivedMac != calculatedMac:
    card.secureChannel.open = false
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  let plaintext = aesCbcDecrypt(card.secureChannel.encryptionKey,
                                card.secureChannel.iv,
                                encryptedData)

  card.secureChannel.iv = receivedMac

  if plaintext.len < 2:
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  let sw = (uint16(plaintext[^2]) shl 8) or uint16(plaintext[^1])
  let data = plaintext[0..<plaintext.len-2]

  SecureApduResult(success: true, data: data, sw: sw)

template mapSecureApduError*[T](secureError: SecureApduError;
                               channelNotOpenError: T;
                               transportError: T;
                               secureApduError: T): T =
  ## Helper template to map SecureApduError to command-specific error types
  ## This eliminates code duplication across command implementations
  case secureError
  of SecureApduChannelNotOpen:
    channelNotOpenError
  of SecureApduTransportError:
    transportError
  of SecureApduInvalidMac:
    secureApduError
  else:
    secureApduError

template checkSecureChannelOpen*[R](card: Keycard; resultType: typedesc[R];
                                    channelNotOpenError: auto): untyped =
  ## Helper template to check if secure channel is open
  ## Returns early with error if channel is not open
  ## Usage: checkSecureChannelOpen(card, SignResult, SignChannelNotOpen)
  if not card.secureChannel.open:
    return resultType(success: false, error: channelNotOpenError, sw: 0)
 
template checkCapability*[R](card: Keycard; hasCapability: bool;
                             resultType: typedesc[R];
                             capabilityError: auto): untyped =
  ## Helper template to check if card has required capability
  ## Returns early with error if capability is not supported
  ## Usage: checkCapability(card, card.appInfo.hasKeyManagement(), SignResult, SignCapabilityNotSupported)
  if not hasCapability:
    return resultType(success: false, error: capabilityError, sw: 0)

proc sendSecure*(card: var Keycard;
                 ins: byte;
                 cla: byte = ClaProprietary;
                 p1: byte = 0x00;
                 p2: byte = 0x00;
                 data: seq[byte] = @[]): SecureApduResult =
  ## Send an encrypted APDU over the secure channel
  ##
  ## This handles:
  ## - Encrypting the data
  ## - Calculating and appending MAC
  ## - Sending the encrypted APDU
  ## - Decrypting and verifying the response
  ##
  ## Note: After secure channel is open, all responses have SW 0x9000
  ## The real SW is in the decrypted response data

  if not card.secureChannel.open:
    return SecureApduResult(success: false, error: SecureApduChannelNotOpen)

  let encryptedData = card.encryptApdu(cla, ins, p1, p2, data)

  let transportResult = card.transport.send(
    ins = ins,
    cla = cla,
    p1 = p1,
    p2 = p2,
    data = encryptedData
  )

  if not transportResult.success:
    return SecureApduResult(success: false, error: SecureApduTransportError)

  let resp = transportResult.value

  if resp.sw != SwSuccess:
    card.secureChannel.open = false
    return SecureApduResult(success: true, data: @[], sw: resp.sw)

  card.decryptResponse(resp.data)