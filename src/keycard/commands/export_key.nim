## EXPORT KEY command implementation
## Exports public and private keys from the card
 
import ../keycard
import ../constants
import ../secure_apdu
import ../tlv
import ../util
 
type
  DerivationOption* = enum
    CurrentKey = 0x00         # Export current key without derivation
    Derive = 0x01             # Derive path but don't change current
    DeriveAndMakeCurrent = 0x02  # Derive path and make it current
 
  ExportOption* = enum
    PrivateAndPublic = 0x00   # Export both private and public key
    PublicOnly = 0x01         # Export public key only
    ExtendedPublic = 0x02     # Export extended public key (with chain code)
 
  ExportKeyError* = enum
    ExportKeyOk
    ExportKeyTransportError
    ExportKeyPrivateNotExportable
    ExportKeyInvalidPath
    ExportKeyInvalidParams
    ExportKeyFailed
    ExportKeyCapabilityNotSupported  # Key management capability required
    ExportKeySecureApduError
    ExportKeyChannelNotOpen
    ExportKeyConditionsNotMet      # PIN not verified
    ExportKeyInvalidResponse
 
  ExportKeyResult* = object
    case success*: bool
    of true:
      publicKey*: seq[byte]     # Empty if P2=0x00 and card omitted it
      privateKey*: seq[byte]    # Empty if P2!=0x00
      chainCode*: seq[byte]     # Empty if P2!=0x02
    of false:
      error*: ExportKeyError
      sw*: uint16
 
proc exportKey*(
  card: var Keycard;
  derivation: DerivationOption = CurrentKey;
  exportOpt: ExportOption = PublicOnly;
  path: openArray[uint32] = [];
  deriveSource: uint8 = DeriveMaster
): ExportKeyResult =
  ## Export public and/or private keys from the card
  ##
  ## Args:
  ##   derivation: How to derive the key (CurrentKey, Derive, or DeriveAndMakeCurrent)
  ##   exportOpt: What to export (PrivateAndPublic, PublicOnly, or ExtendedPublic)
  ##   path: BIP32 derivation path (empty if derivation=CurrentKey)
  ##   deriveSource: Source for derivation (DeriveMaster, DeriveParent, or DeriveCurrent)
  ##
  ## Preconditions:
  ##   - Secure Channel must be opened
  ##   - User PIN must be verified
  ##   - Key management capability required
  ##
  ## Key export rules:
  ##   - Public key can always be exported (exportOpt=PublicOnly)
  ##   - Private key can only be exported if path is in EIP-1581 subtree
  ##   - Extended public key can be exported for any path except EIP-1581 subtree
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6985 if private key cannot be exported
  ##   0x6A80 if path is malformed
  ##   0x6A86 if P1 or P2 are wrong
  ##
  ## Response Data:
  ##   Tag 0xA1 = keypair template
  ##     Tag 0x80 = ECC public key component (omitted if exportOpt=PrivateAndPublic)
  ##     Tag 0x81 = ECC private key component (if exportOpt=PrivateAndPublic)
  ##     Tag 0x82 = Chain code (if exportOpt=ExtendedPublic)
 
  checkCapability(card, card.appInfo.hasKeyManagement(), ExportKeyResult, ExportKeyCapabilityNotSupported)
  checkSecureChannelOpen(card, ExportKeyResult, ExportKeyChannelNotOpen)
 
  let p1 = byte(derivation) or deriveSource
 
  let p2 = byte(exportOpt)
 
  let data = if derivation == CurrentKey:
    @[]
  else:
    encodeBip32Path(path)
 
  let secureResult = card.sendSecure(
    ins = InsExportKey,
    p1 = p1,
    p2 = p2,
    data = data
  )
 
  if not secureResult.success:
    let exportError = mapSecureApduError(
      secureResult.error,
      ExportKeyChannelNotOpen,
      ExportKeyTransportError,
      ExportKeySecureApduError
    )
    return ExportKeyResult(success: false,
                          error: exportError,
                          sw: 0)
 
  case secureResult.sw
  of SwSuccess:
    discard
  of SwConditionsNotSatisfied:
    return ExportKeyResult(success: false,
                          error: ExportKeyPrivateNotExportable,
                          sw: secureResult.sw)
  of SwWrongData:
    return ExportKeyResult(success: false,
                          error: ExportKeyInvalidPath,
                          sw: secureResult.sw)
  of SwIncorrectP1P2:
    return ExportKeyResult(success: false,
                          error: ExportKeyInvalidParams,
                          sw: secureResult.sw)
  else:
    return ExportKeyResult(success: false,
                          error: ExportKeyFailed,
                          sw: secureResult.sw)
 
  let tags = parseTlv(secureResult.data)
  let keypairTemplate = findTag(tags, TagKeypairTemplate)
 
  if keypairTemplate.len == 0:
    return ExportKeyResult(success: false,
                          error: ExportKeyInvalidResponse,
                          sw: secureResult.sw)
 
  let innerTags = parseTlv(keypairTemplate)
 
  var publicKey: seq[byte] = @[]
  var privateKey: seq[byte] = @[]
  var chainCode: seq[byte] = @[]
 
  for tag in innerTags:
    case tag.tag
    of TagTlvPublicKey:  # Public key
      publicKey = tag.value
    of TagTlvPrivateKey:  # Private key
      privateKey = tag.value
    of TagTlvChainCode:  # Chain code
      chainCode = tag.value
    else:
      discard
 
  return ExportKeyResult(success: true,
                        publicKey: publicKey,
                        privateKey: privateKey,
                        chainCode: chainCode)
