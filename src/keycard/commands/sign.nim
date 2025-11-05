## SIGN command implementation
## Signs data using various cryptographic algorithms

import ../keycard
import ../constants
import ../secure_apdu
import ../tlv

# Derivation source constants (can be OR'd with P1)
# These match the DERIVE KEY and EXPORT KEY command specifications
const
  DeriveMaster* = 0x00'u8    # Derive from master key
  DeriveParent* = 0x40'u8    # Derive from parent key
  DeriveCurrent* = 0x80'u8   # Derive from current key

type
  SignDerivationOption* = enum
    SignCurrentKey = 0x00         # Sign with current key
    SignDerive = 0x01             # Derive path but don't change current
    SignDeriveAndMakeCurrent = 0x02  # Derive path and make it current
    SignPinlessPath = 0x03        # Use PIN-less path (no secure channel needed)

  SignAlgorithm* = enum
    EcdsaSecp256k1 = 0x00    # ECDSA over secp256k1 (currently supported)
    EddsaEd25519 = 0x01      # EdDSA over ed25519 (placeholder)
    Bls12_381 = 0x02         # BLS12-381 (placeholder)
    Bip340Schnorr = 0x03     # BIP340 Schnorr (placeholder)

  SignError* = enum
    SignOk
    SignTransportError
    SignDataTooShort           # SW 0x6A80
    SignNoPinlessPath          # SW 0x6A88
    SignAlgorithmNotSupported  # SW 0x6A81
    SignFailed
    SignCapabilityNotSupported  # Key management capability required
    SignSecureApduError
    SignChannelNotOpen
    SignConditionsNotMet       # PIN not verified or no key loaded
    SignInvalidResponse

  SignResult* = object
    case success*: bool
    of true:
      signature*: seq[byte]      # Raw signature (65 bytes for ECDSA: r, s, recId)
      publicKey*: seq[byte]      # Optional: present if signature template format used
    of false:
      error*: SignError
      sw*: uint16

proc encodeSignPath(path: openArray[uint32]): seq[byte] =
  ## Encode a sequence of 32-bit integers as big-endian bytes
  result = newSeq[byte](path.len * 4)
  for i, value in path:
    let offset = i * 4
    result[offset] = byte((value shr 24) and 0xFF)
    result[offset + 1] = byte((value shr 16) and 0xFF)
    result[offset + 2] = byte((value shr 8) and 0xFF)
    result[offset + 3] = byte(value and 0xFF)

proc parseEcdsaSignature(derEncoded: seq[byte]): seq[byte] =
  ## Parse DER-encoded ECDSA signature contents (without SEQUENCE wrapper) to extract r and s values
  ## derEncoded should be the VALUE of tag 0x30, starting directly with INTEGER tags
  ## Returns empty seq if parsing fails
  ## Note: This does not include recovery ID - will need to be calculated
  if derEncoded.len < 6:
    return @[]

  # We receive the contents of the SEQUENCE, not the SEQUENCE tag itself
  # So we start directly at the first INTEGER tag
  var pos = 0

  if pos >= derEncoded.len or derEncoded[pos] != 0x02:  # INTEGER tag
    return @[]
  inc pos

  let rLen = int(derEncoded[pos])
  inc pos

  if pos + rLen > derEncoded.len:
    return @[]

  var rValue = derEncoded[pos ..< pos + rLen]
  pos += rLen

  if pos >= derEncoded.len or derEncoded[pos] != 0x02:  # INTEGER tag
    return @[]
  inc pos

  let sLen = int(derEncoded[pos])
  inc pos

  if pos + sLen > derEncoded.len:
    return @[]

  var sValue = derEncoded[pos ..< pos + sLen]

  while rValue.len > 0 and rValue[0] == 0:
    rValue = rValue[1 .. ^1]
  while sValue.len > 0 and sValue[0] == 0:
    sValue = sValue[1 .. ^1]

  while rValue.len < 32:
    rValue = @[byte(0)] & rValue
  while sValue.len < 32:
    sValue = @[byte(0)] & sValue

  result = rValue & sValue

proc sign*(
  card: var Keycard;
  hash: openArray[byte];
  derivation: SignDerivationOption = SignCurrentKey;
  algorithm: SignAlgorithm = EcdsaSecp256k1;
  path: openArray[uint32] = [];
  deriveSource: uint8 = DeriveMaster
): SignResult =
  ## Sign a 32-byte hash using the specified algorithm
  ##
  ## Args:
  ##   hash: The 32-byte hash to sign
  ##   derivation: How to derive the key (SignCurrentKey, SignDerive, SignDeriveAndMakeCurrent, or SignPinlessPath)
  ##   algorithm: Signing algorithm (only EcdsaSecp256k1 currently supported on Keycard)
  ##   path: BIP32 derivation path (required if derivation=SignDerive or SignDeriveAndMakeCurrent)
  ##   deriveSource: Source for derivation (DeriveMaster, DeriveParent, or DeriveCurrent)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened (except for derivation=SignPinlessPath)
  ##   - User PIN must be verified (or PIN-less key active for derivation=SignPinlessPath)
  ##   - Valid keypair must be loaded
  ##   - Key management capability required
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if data is less than 32 bytes (or 36 bytes if derivation path specified)
  ##   0x6A88 if derivation=SignPinlessPath but no PIN-less path defined
  ##   0x6A81 if algorithm is not supported
  ##
  ## Response Data:
  ##   For ECDSA: 65-byte signature (r, s, recId) or signature template with public key
  ##
  ## Note: If signature template format is returned, recovery ID must be calculated
  ## by trying values 0-3 and checking if recovered public key matches

  if not card.appInfo.hasKeyManagement():
    return SignResult(success: false,
                     error: SignCapabilityNotSupported,
                     sw: 0)

  if derivation != SignPinlessPath:
    if not card.secureChannel.open:
      return SignResult(success: false,
                       error: SignChannelNotOpen,
                       sw: 0)

  if hash.len != 32:
    return SignResult(success: false,
                     error: SignDataTooShort,
                     sw: 0x6A80)

  let p1 = byte(derivation) or deriveSource

  let p2 = byte(algorithm)

  var data = @hash
  if derivation == SignDerive or derivation == SignDeriveAndMakeCurrent:
    data.add(encodeSignPath(path))

  let secureResult = card.sendSecure(
    ins = InsSign,
    p1 = p1,
    p2 = p2,
    data = data
  )

  if not secureResult.success:
    let signError = case secureResult.error
      of SecureApduChannelNotOpen:
        SignChannelNotOpen
      of SecureApduTransportError:
        SignTransportError
      of SecureApduInvalidMac:
        SignSecureApduError
      else:
        SignSecureApduError

    return SignResult(success: false,
                     error: signError,
                     sw: 0)

  case secureResult.sw
  of SwSuccess:
    discard
  of 0x6A80:
    return SignResult(success: false,
                     error: SignDataTooShort,
                     sw: secureResult.sw)
  of 0x6A88:
    return SignResult(success: false,
                     error: SignNoPinlessPath,
                     sw: secureResult.sw)
  of 0x6A81:
    return SignResult(success: false,
                     error: SignAlgorithmNotSupported,
                     sw: secureResult.sw)
  of 0x6985:
    return SignResult(success: false,
                     error: SignConditionsNotMet,
                     sw: secureResult.sw)
  else:
    return SignResult(success: false,
                     error: SignFailed,
                     sw: secureResult.sw)

  let tags = parseTlv(secureResult.data)

  let rawSig = findTag(tags, 0x80)
  if rawSig.len > 0:
    return SignResult(success: true,
                     signature: rawSig,
                     publicKey: @[])

  let sigTemplate = findTag(tags, 0xA0)
  if sigTemplate.len > 0:
    let innerTags = parseTlv(sigTemplate)

    var publicKey: seq[byte] = @[]
    var signature: seq[byte] = @[]

    for tag in innerTags:
      case tag.tag
      of 0x80:  # Public key
        publicKey = tag.value
      of 0x30:  # ECDSA signature (DER encoded)
        signature = parseEcdsaSignature(tag.value)
      else:
        discard

    if signature.len == 0:
      return SignResult(success: false,
                       error: SignInvalidResponse,
                       sw: secureResult.sw)

    return SignResult(success: true,
                     signature: signature,
                     publicKey: publicKey)

  return SignResult(success: false,
                   error: SignInvalidResponse,
                   sw: secureResult.sw)
