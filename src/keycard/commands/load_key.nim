## LOAD KEY command implementation
## Loads or replaces keypair used for signing on the card

import ../keycard
import ../constants
import ../secure_apdu
import ../tlv

type
  KeyType* = enum
    EccKeypair = 0x01           # ECC SECP256k1 keypair
    EccExtendedKeypair = 0x02   # ECC SECP256k1 extended keypair
    Bip39Seed = 0x03            # Binary seed as defined in BIP39

  LoadKeyError* = enum
    LoadKeyOk
    LoadKeyTransportError
    LoadKeyInvalidFormat
    LoadKeyInvalidKeyType
    LoadKeyFailed
    LoadKeyCapabilityNotSupported
    LoadKeySecureApduError
    LoadKeyChannelNotOpen
    LoadKeyConditionsNotMet     # PIN not verified

  LoadKeyResult* = object
    case success*: bool
    of true:
      keyUID*: seq[byte]  # SHA-256 of the public key
    of false:
      error*: LoadKeyError
      sw*: uint16

proc loadKey*(
  card: var Keycard;
  keyType: KeyType;
  privateKey: openArray[byte];
  publicKey: openArray[byte] = [];
  chainCode: openArray[byte] = []
): LoadKeyResult =
  ## Load or replace keypair on the card
  ##
  ## Args:
  ##   keyType: Type of key (EccKeypair, EccExtendedKeypair, or Bip39Seed)
  ##   privateKey: Private key bytes (32 bytes for ECC, 64 bytes for BIP39 seed)
  ##   publicKey: Public key bytes (optional, 65 bytes uncompressed for ECC)
  ##   chainCode: Chain code bytes (required for EccExtendedKeypair, 32 bytes)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - User PIN must be verified
  ##   - Key management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if format is invalid
  ##   0x6A86 if P1 (key type) is invalid
  ##
  ## Response Data:
  ##   Key UID (SHA-256 of the public key)
  ##
  ## Notes:
  ##   - PIN-less path will be reset
  ##   - Loaded key becomes current key for signing
  ##   - BIP39 seed only supported if hardware supports public key derivation

  checkCapability(card, card.appInfo.hasKeyManagement(), LoadKeyResult, LoadKeyCapabilityNotSupported)
  checkSecureChannelOpen(card, LoadKeyResult, LoadKeyChannelNotOpen)

  # Build the key data based on key type
  let data = case keyType
    of Bip39Seed:
      # BIP39 seed is just raw 64-byte data
      @privateKey
    of EccKeypair:
      # ECC keypair uses TLV template
      encodeKeypairTemplate(publicKey, privateKey)
    of EccExtendedKeypair:
      # Extended keypair includes chain code
      encodeKeypairTemplate(publicKey, privateKey, chainCode)

  let secureResult = card.sendSecure(
    ins = InsLoadKey,
    p1 = byte(keyType),
    data = data
  )

  if not secureResult.success:
    let loadError = mapSecureApduError(
      secureResult.error,
      LoadKeyChannelNotOpen,
      LoadKeyTransportError,
      LoadKeySecureApduError
    )
    return LoadKeyResult(success: false,
                        error: loadError,
                        sw: 0)

  case secureResult.sw
  of SwSuccess:
    return LoadKeyResult(success: true, keyUID: secureResult.data)
  of SwWrongData:
    return LoadKeyResult(success: false,
                        error: LoadKeyInvalidFormat,
                        sw: secureResult.sw)
  of SwIncorrectP1P2:
    return LoadKeyResult(success: false,
                        error: LoadKeyInvalidKeyType,
                        sw: secureResult.sw)
  of SwConditionsNotSatisfied:
    return LoadKeyResult(success: false,
                        error: LoadKeyConditionsNotMet,
                        sw: secureResult.sw)
  else:
    return LoadKeyResult(success: false,
                        error: LoadKeyFailed,
                        sw: secureResult.sw)
