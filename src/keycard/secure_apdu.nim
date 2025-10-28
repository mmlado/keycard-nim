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
  ##
  ## Process:
  ## 1. Pad data using ISO/IEC 9797-1 Method 2
  ## 2. Encrypt using AES-CBC with session key and current IV
  ## 3. Calculate MAC over entire APDU (CLA INS P1 P2 LC + padding + encrypted data)
  ## 4. Return MAC + encrypted data

  # Encrypt the data using current IV
  let encrypted = aesCbcEncrypt(card.secureChannel.encryptionKey,
                                card.secureChannel.iv,
                                data)

  # Build MAC input: CLA INS P1 P2 LC + 11-byte padding + encrypted data
  var macInput: seq[byte] = @[]
  macInput.add(cla)
  macInput.add(ins)
  macInput.add(p1)
  macInput.add(p2)
  macInput.add(byte(encrypted.len + 16))  # LC includes MAC length

  # Add 11-byte padding for MAC calculation
  for i in 0..<11:
    macInput.add(0x00)

  macInput.add(encrypted)

  # Calculate MAC (uses zero IV internally)
  let mac = aesCbcMac(card.secureChannel.macKey, macInput)

  # Update IV for next encryption (IV = last MAC from our side)
  card.secureChannel.iv = mac

  # Return MAC + encrypted data
  result = @[]
  result.add(mac)
  result.add(encrypted)

proc decryptResponse*(card: var Keycard; response: seq[byte]): SecureApduResult =
  ## Decrypt R-APDU response from secure channel
  ##
  ## Process:
  ## 1. Extract MAC (first 16 bytes)
  ## 2. Verify MAC over Lr + padding + encrypted data
  ## 3. Decrypt remaining data using AES-CBC
  ## 4. Remove padding
  ## 5. Extract real SW from last 2 bytes of plaintext

  if response.len < 16:
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  # Extract MAC
  let receivedMac = response[0..<16]
  let encryptedData = response[16..^1]

  # Build MAC input: Lr + 15-byte padding + encrypted data
  # Lr is the length of encrypted response data
  var macInput: seq[byte] = @[]
  macInput.add(byte(encryptedData.len))

  # Add 15-byte padding for MAC calculation
  for i in 0..<15:
    macInput.add(0x00)

  macInput.add(encryptedData)

  # Calculate MAC and verify
  let calculatedMac = aesCbcMac(card.secureChannel.macKey, macInput)

  if receivedMac != calculatedMac:
    # MAC verification failed - secure channel must be closed
    card.secureChannel.open = false
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  # Update IV for next decryption (IV = last MAC from card)
  card.secureChannel.iv = receivedMac

  # Decrypt data
  let plaintext = aesCbcDecrypt(card.secureChannel.encryptionKey,
                                receivedMac,  # Use received MAC as IV
                                encryptedData)

  # Extract real SW from last 2 bytes
  if plaintext.len < 2:
    return SecureApduResult(success: false, error: SecureApduInvalidMac)

  let sw = (uint16(plaintext[^2]) shl 8) or uint16(plaintext[^1])
  let data = plaintext[0..<plaintext.len-2]

  SecureApduResult(success: true, data: data, sw: sw)

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

  # Encrypt and build APDU
  let encryptedData = card.encryptApdu(cla, ins, p1, p2, data)

  # Send encrypted APDU
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

  # Check for 0x6982 (secure channel aborted - returned without MAC)
  if resp.sw == 0x6982:
    card.secureChannel.open = false
    return SecureApduResult(success: true, data: @[], sw: 0x6982)

  # All other responses should be 0x9000 with encrypted data
  if resp.sw != SwSuccess:
    # Unexpected status word
    card.secureChannel.open = false
    return SecureApduResult(success: true, data: @[], sw: resp.sw)

  # Decrypt and verify response
  card.decryptResponse(resp.data)