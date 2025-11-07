## OPEN SECURE CHANNEL command implementation
## Opens a secure channel using ECDH key exchange

import ../keycard
import ../constants
import ../apdu
import ../transport
import ../crypto/utils
import mutually_authenticate

type
  OpenSecureChannelError* = enum
    OpenSecureChannelOk
    OpenSecureChannelTransportError
    OpenSecureChannelInvalidP1
    OpenSecureChannelInvalidData
    OpenSecureChannelFailed
    OpenSecureChannelNotSelected
    OpenSecureChannelInvalidResponse
    OpenSecureChannelMutualAuthFailed  # Mutual authentication failed

  OpenSecureChannelResult* = object
    case success*: bool
    of true:
      salt*: seq[byte]
      iv*: seq[byte]
    of false:
      error*: OpenSecureChannelError
      sw*: uint16

proc openSecureChannel*(card: var Keycard;
                       pairingIndex: byte;
                       pairingKey: seq[byte];
                       authenticate: bool = true): OpenSecureChannelResult =
  ## Open a secure channel with the card
  ##
  ## Args:
  ##   pairingIndex: Index of the pairing slot (0-4)
  ##   pairingKey: 32-byte pairing key obtained during pairing
  ##   authenticate: Automatically call MUTUALLY AUTHENTICATE (default: true)
  ##
  ## This establishes session keys via ECDH key exchange.
  ## If authenticate=true (default), automatically performs MUTUALLY AUTHENTICATE
  ## to verify both parties have matching keys.
  ##
  ## OPEN SECURE CHANNEL APDU:
  ##   CLA = 0x80
  ##   INS = 0x10
  ##   P1 = pairing index
  ##   P2 = 0x00
  ##   Data = EC-256 public key (uncompressed, 65 bytes)
  ##   Response: 256-bit salt (32 bytes) + 128-bit IV (16 bytes)

  if card.publicKey.len == 0:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelNotSelected,
                                   sw: 0)

  if pairingKey.len != Sha256Size:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelInvalidData,
                                   sw: 0)

  let (clientPrivate, clientPublic) = generateEcdhKeypair()

  let transportResult = card.transport.send(
    ins = InsOpenSecureChannel,
    p1 = pairingIndex,
    data = clientPublic
  )

  if not transportResult.success:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelTransportError,
                                   sw: 0)

  let resp = transportResult.value

  case resp.sw
  of SwSuccess:
    discard
  of SwIncorrectP1P2:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelInvalidP1,
                                   sw: resp.sw)
  of SwWrongData:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelInvalidData,
                                   sw: resp.sw)
  else:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelFailed,
                                   sw: resp.sw)

  if resp.data.len != 48:
    return OpenSecureChannelResult(success: false,
                                   error: OpenSecureChannelInvalidResponse,
                                   sw: resp.sw)

  let salt = resp.data[0..<Sha256Size]
  let iv = resp.data[Sha256Size..<(Sha256Size + AesBlockSize)]

  let sharedSecret = ecdhSharedSecret(clientPrivate, card.publicKey)

  let (encKey, macKey) = deriveSessionKeys(sharedSecret, pairingKey, salt)

  card.secureChannel.open = true
  card.secureChannel.encryptionKey = encKey
  card.secureChannel.macKey = macKey
  card.secureChannel.iv = iv
  card.secureChannel.pairingIndex = pairingIndex

  if authenticate:
    let mutualAuthResult = card.mutuallyAuthenticate()

    if not mutualAuthResult.success:
      return OpenSecureChannelResult(success: false,
                                     error: OpenSecureChannelMutualAuthFailed,
                                     sw: mutualAuthResult.sw)

  OpenSecureChannelResult(success: true, salt: salt, iv: iv)
