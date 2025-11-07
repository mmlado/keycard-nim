## IDENT command implementation
## Identifies the card by signing a challenge

import ../keycard
import ../constants
import ../transport
import ../tlv
import ../crypto/utils

type
  IdentError* = enum
    IdentOk
    IdentTransportError
    IdentInvalidFormat
    IdentFailed
    IdentInvalidResponse
    IdentSignatureVerificationFailed

  IdentResult* = object
    case success*: bool
    of true:
      certificate*: seq[byte]    # Card's certificate (98 bytes)
      signature*: seq[byte]      # Challenge signature (DER encoded)
      publicKey*: seq[byte]      # Card's identification public key (33 bytes compressed)
    of false:
      error*: IdentError
      sw*: uint16

proc ident*(card: var Keycard; challenge: seq[byte] = @[]): IdentResult =
  ## Identify the card by signing a challenge
  ##
  ## Args:
  ##   challenge: 32-byte challenge to sign (generated if empty)
  ##
  ## This command does not require PIN authentication or secure channel.
  ## Recommended to perform before initializing or pairing with the card.
  ##
  ## IDENT APDU:
  ##   CLA = 0x80
  ##   INS = 0x14
  ##   P1 = 0x00
  ##   P2 = 0x00
  ##   Data = 32-byte challenge
  ##
  ## Response SW:
  ##   0x9000 on success
  ##   0x6A80 if format is invalid
  ##
  ## Response Data (TLV):
  ##   Tag 0xA0 = signature template
  ##     Tag 0x8A = Certificate (33 bytes compressed public key +
  ##                             64 bytes r,s signature +
  ##                             1 byte recovery id)
  ##     Tag 0x30 = ECDSA Signature (DER encoded)

  # Generate random challenge if not provided
  let actualChallenge = if challenge.len == 0:
    generateRandomBytes(Sha256Size)
  else:
    challenge

  if actualChallenge.len != Sha256Size:
    return IdentResult(success: false,
                      error: IdentInvalidFormat,
                      sw: 0)

  # Send IDENT command
  let transportResult = card.transport.send(
    ins = InsIdent,
    data = actualChallenge
  )

  if not transportResult.success:
    return IdentResult(success: false,
                      error: IdentTransportError,
                      sw: 0)

  let resp = transportResult.value

  # Check status word
  case resp.sw
  of SwSuccess:
    discard  # Continue to parse response
  of SwWrongData:
    return IdentResult(success: false,
                      error: IdentInvalidFormat,
                      sw: resp.sw)
  else:
    return IdentResult(success: false,
                      error: IdentFailed,
                      sw: resp.sw)

  # Parse TLV response
  let outerTags = parseTlv(resp.data)
  let signatureTemplate = findTag(outerTags, TagSignatureTemplate)

  if signatureTemplate.len == 0:
    return IdentResult(success: false,
                      error: IdentInvalidResponse,
                      sw: resp.sw)

  # Parse inner TLV (inside 0xA0)
  let innerTags = parseTlv(signatureTemplate)
  let certificate = findTag(innerTags, 0x8A)
  let signature = findTag(innerTags, TagDerSequence)

  if certificate.len < (Secp256k1UncompressedSize + Sha256Size) or signature.len < Secp256k1UncompressedSize:
    return IdentResult(success: false,
                      error: IdentInvalidResponse,
                      sw: resp.sw)

  # Extract public key (first 33 bytes of certificate)
  let publicKey = certificate[0..<33]

  return IdentResult(success: true,
                    certificate: certificate,
                    signature: signature,
                    publicKey: publicKey)