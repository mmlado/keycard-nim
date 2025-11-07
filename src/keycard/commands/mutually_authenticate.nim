## MUTUALLY AUTHENTICATE command implementation
## Verifies that both parties have matching session keys

import ../keycard
import ../constants
import ../apdu
import ../transport
import ../crypto/utils

type
  MutuallyAuthenticateError* = enum
    MutuallyAuthenticateOk
    MutuallyAuthenticateTransportError
    MutuallyAuthenticateChannelNotOpen
    MutuallyAuthenticateFailed
    MutuallyAuthenticateNotAfterOpen
    MutuallyAuthenticateMacVerifyFailed
    MutuallyAuthenticateInvalidResponse

  MutuallyAuthenticateResult* = object
    case success*: bool
    of true:
      discard
    of false:
      error*: MutuallyAuthenticateError
      sw*: uint16

proc mutuallyAuthenticate*(card: var Keycard): MutuallyAuthenticateResult =
  ## Perform mutual authentication over the secure channel
  ##
  ## This APDU allows both parties to verify that the keys generated in the
  ## OPEN SECURE CHANNEL step are matching and thus guarantee authentication
  ## of the counterpart.
  ##
  ## The data sent by both parties is a 256-bit random number.
  ## If the MAC can be verified, it means that both parties are using the same keys.
  ##
  ## Only after this step has been executed should the secure channel be
  ## considered fully open and other commands can be sent.
  ##
  ## APDU format (sent over secure channel):
  ##   CLA = 0x80
  ##   INS = 0x11
  ##   P1 = 0x00
  ##   P2 = 0x00
  ##   Data = 256-bit random challenge (encrypted)
  ##
  ## Response:
  ##   256-bit random response (encrypted)
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6985 if previous command was not OPEN SECURE CHANNEL
  ##   0x6982 if authentication failed

  if not card.secureChannel.open:
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateChannelNotOpen,
                                      sw: 0)

  let clientChallenge = generateRandomBytes(Sha256Size)

  let encryptedChallenge = aesCbcEncrypt(card.secureChannel.encryptionKey,
                                         card.secureChannel.iv,
                                         clientChallenge)

  var macInput: seq[byte] = @[]
  macInput.add(ClaProprietary)
  macInput.add(InsMutuallyAuthenticate)
  macInput.add(0x00)  # P1
  macInput.add(0x00)  # P2
  macInput.add(byte(encryptedChallenge.len + AesMacSize))

  for i in 0..<11:
    macInput.add(0x00)

  macInput.add(encryptedChallenge)

  let mac = aesCbcMac(card.secureChannel.macKey, macInput)

  card.secureChannel.iv = mac

  var mutualAuthData: seq[byte] = @[]
  mutualAuthData.add(mac)
  mutualAuthData.add(encryptedChallenge)

  let mutualAuthResult = card.transport.send(
    ins = InsMutuallyAuthenticate,
    data = mutualAuthData
  )

  if not mutualAuthResult.success:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateTransportError,
                                      sw: 0)

  let mutualAuthResp = mutualAuthResult.value

  if mutualAuthResp.sw == SwSecurityStatusNotSatisfied:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateFailed,
                                      sw: mutualAuthResp.sw)

  if mutualAuthResp.sw == SwConditionsNotSatisfied:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateNotAfterOpen,
                                      sw: mutualAuthResp.sw)

  if mutualAuthResp.sw != SwSuccess:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateFailed,
                                      sw: mutualAuthResp.sw)

  if mutualAuthResp.data.len < AesMacSize:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateInvalidResponse,
                                      sw: mutualAuthResp.sw)

  let receivedMac = mutualAuthResp.data[0..<AesMacSize]
  let encryptedResponse = mutualAuthResp.data[AesMacSize..^1]

  var responseMacInput: seq[byte] = @[]
  responseMacInput.add(byte(mutualAuthResp.data.len))

  for i in 0..<15:
    responseMacInput.add(0x00)

  responseMacInput.add(encryptedResponse)

  let calculatedMac = aesCbcMac(card.secureChannel.macKey, responseMacInput)

  if receivedMac != calculatedMac:
    card.secureChannel.open = false
    return MutuallyAuthenticateResult(success: false,
                                      error: MutuallyAuthenticateMacVerifyFailed,
                                      sw: 0)

  card.secureChannel.iv = receivedMac

  MutuallyAuthenticateResult(success: true)