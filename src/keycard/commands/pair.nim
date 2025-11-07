## PAIR command implementation
## Establishes a pairing between client and card (two-step process)

import ../keycard
import ../constants
import ../apdu
import ../transport
import ../crypto/utils
import nimcrypto/[hash, sha2]

type
  PairError* = enum
    PairOk
    PairTransportError
    PairInvalidP1
    PairInvalidData
    PairCryptogramFailed
    PairSlotsFull
    PairSecureChannelOpen
    PairFailed
    PairNotInitialized
    PairInvalidResponse
    PairCardAuthFailed     # Card cryptogram verification failed

  PairResult* = object
    case success*: bool
    of true:
      pairingIndex*: byte
      pairingKey*: seq[byte]  # The derived pairing key to use for secure channel
      salt*: seq[byte]        # 32-byte salt
    of false:
      error*: PairError
      sw*: uint16

proc computeCryptogram(data1: seq[byte], data2: seq[byte]): seq[byte] =
  ## Compute SHA-256 hash of concatenated data
  ## Used for card/client cryptogram and pairing key derivation
  var combined: seq[byte] = @[]
  combined.add(data1)
  combined.add(data2)

  var ctx: sha256
  ctx.init()
  ctx.update(combined)
  let hash = ctx.finish()
  result = @(hash.data)

proc pair*(card: var Keycard;
           pairingPassword: string): PairResult =
  ## Pair with the card to establish a pairing slot (two-step process)
  ##
  ## Args:
  ##   pairingPassword: Pairing password (same as used in INIT)
  ##
  ## This command must be executed after INIT and before OPEN SECURE CHANNEL.
  ## It performs mutual authentication and creates a pairing entry.
  ##
  ## Step 1 (P1 = 0x00):
  ##   Client sends: 256-bit random client challenge
  ##   Card responds: SHA-256(shared secret, client challenge) + 256-bit card challenge
  ##
  ## Step 2 (P1 = 0x01):
  ##   Client sends: SHA-256(shared secret, card challenge)
  ##   Card responds: pairing index + 256-bit salt

  if card.publicKey.len == 0:
    return PairResult(success: false,
                     error: PairNotInitialized,
                     sw: 0)

  let sharedSecret = generatePairingToken(pairingPassword)

  # Step 1: Send client challenge
  let clientChallenge = generateRandomBytes(Sha256Size)

  let step1Result = card.transport.send(
    ins = InsPair,
    data = clientChallenge
  )

  if not step1Result.success:
    return PairResult(success: false,
                     error: PairTransportError,
                     sw: 0)

  let step1Resp = step1Result.value

  case step1Resp.sw
  of SwSuccess:
    discard
  of SwIncorrectP1P2:
    return PairResult(success: false,
                     error: PairInvalidP1,
                     sw: step1Resp.sw)
  of SwWrongData:
    return PairResult(success: false,
                     error: PairInvalidData,
                     sw: step1Resp.sw)
  of SwNotEnoughMemory:
    return PairResult(success: false,
                     error: PairSlotsFull,
                     sw: step1Resp.sw)
  of SwConditionsNotSatisfied:
    return PairResult(success: false,
                     error: PairSecureChannelOpen,
                     sw: step1Resp.sw)
  else:
    return PairResult(success: false,
                     error: PairFailed,
                     sw: step1Resp.sw)

  if step1Resp.data.len != (Sha256Size * 2):
    return PairResult(success: false,
                     error: PairInvalidResponse,
                     sw: step1Resp.sw)

  let cardCryptogram = step1Resp.data[0..<Sha256Size]
  let cardChallenge = step1Resp.data[Sha256Size..<(Sha256Size * 2)]

  # Verify card cryptogram
  let expectedCardCryptogram = computeCryptogram(sharedSecret, clientChallenge)
  if cardCryptogram != expectedCardCryptogram:
    return PairResult(success: false,
                     error: PairCardAuthFailed,
                     sw: 0)

  # Step 2: Send client cryptogram
  let clientCryptogram = computeCryptogram(sharedSecret, cardChallenge)

  let step2Result = card.transport.send(
    ins = InsPair,
    p1 = 0x01,  # Second step
    p2 = 0x00,
    data = clientCryptogram
  )

  if not step2Result.success:
    return PairResult(success: false,
                     error: PairTransportError,
                     sw: 0)

  let step2Resp = step2Result.value

  case step2Resp.sw
  of SwSuccess:
    discard
  of SwSecurityStatusNotSatisfied:
    return PairResult(success: false,
                     error: PairCryptogramFailed,
                     sw: step2Resp.sw)
  of SwIncorrectP1P2:
    return PairResult(success: false,
                     error: PairInvalidP1,
                     sw: step2Resp.sw)
  else:
    return PairResult(success: false,
                     error: PairFailed,
                     sw: step2Resp.sw)

  if step2Resp.data.len != 33:
    return PairResult(success: false,
                     error: PairInvalidResponse,
                     sw: step2Resp.sw)

  let pairingIndex = step2Resp.data[0]
  let salt = step2Resp.data[1..<33]

  # Derive pairing key
  let pairingKey = computeCryptogram(sharedSecret, salt)

  PairResult(success: true,
             pairingIndex: pairingIndex,
             pairingKey: pairingKey,
             salt: salt)
