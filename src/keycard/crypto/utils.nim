## Cryptographic utilities for Keycard operations

import std/strutils
import nimcrypto
import nimcrypto/[bcmode, rijndael, sysrand, pbkdf2, hash]
import secp256k1
import secp256k1/abi
import ../constants

proc ecdhRawHashFunc(output: pointer, x32: pointer, y32: pointer, data: pointer): cint {.cdecl, noSideEffect, gcsafe.} =
  copyMem(output, x32, Secp256k1CoordinateSize)
  return 1

proc generateEcdhKeypair*(): tuple[privateKey: seq[byte], publicKey: seq[byte]] =
  ## Generate an ephemeral SECP256K1 keypair for ECDH
  ## Returns (private_key, uncompressed_public_key)
  
  # Generate random 32 bytes for private key
  var privateKeyBytes = newSeq[byte](Secp256k1PrivateKeySize)
  if randomBytes(privateKeyBytes) != Secp256k1PrivateKeySize:
    raise newException(OSError, "Failed to generate random bytes")
  
  var skArray: array[Secp256k1PrivateKeySize, byte]
  for i in 0..<Secp256k1PrivateKeySize:
    skArray[i] = privateKeyBytes[i]
  
  let skResult = SkSecretKey.fromRaw(skArray)
  if skResult.isErr:
    raise newException(ValueError, "Failed to create secret key")
  
  let sk = skResult.get()
  let pk = sk.toPublicKey()
  
  result.privateKey = @(sk.toRaw())
  # Get uncompressed public key (65 bytes)
  var pkArray = pk.toRaw()
  result.publicKey = @pkArray

proc ecdhKeypairFromHex*(privateKeyHex: string): tuple[privateKey: seq[byte], publicKey: seq[byte]] =
  ## Create ECDH keypair from a hex-encoded private key (for testing/debugging)
  ## privateKeyHex: 64-character hex string (32 bytes)
    
  # Parse hex string to bytes
  let privateKeyBytes = parseHexStr(privateKeyHex)
  
  if privateKeyBytes.len != Secp256k1PrivateKeySize:
    raise newException(ValueError, "Private key must be " & $Secp256k1PrivateKeySize & " bytes (64 hex chars)")
  
  var skArray: array[Secp256k1PrivateKeySize, byte]
  for i in 0..<Secp256k1PrivateKeySize:
    skArray[i] = cast[seq[byte]](privateKeyBytes)[i]
  
  let skResult = SkSecretKey.fromRaw(skArray)
  if skResult.isErr:
    raise newException(ValueError, "Invalid private key")
  
  let sk = skResult.get()
  let pk = sk.toPublicKey()
  
  result.privateKey = @(sk.toRaw())
  var pkArray = pk.toRaw()
  result.publicKey = @pkArray

proc ecdhSharedSecret*(privateKey: seq[byte], cardPublicKey: seq[byte]): seq[byte] =
  ## Perform ECDH to derive shared secret
  ## privateKey: our private key (32 bytes)
  ## cardPublicKey: card's public key (65 bytes uncompressed)
  ## Returns: shared secret (32 bytes)
  ## 
  ## Note: Python's ecdsa library uses `generate_sharedsecret_bytes()` which
  ## by default applies SHA-1 hashing to the shared point's x-coordinate.
  ## We need to match that behavior for compatibility.
  
  var skArray: array[Secp256k1PrivateKeySize, byte]
  for i in 0..<Secp256k1PrivateKeySize:
    skArray[i] = privateKey[i]
  
  let sk = SkSecretKey.fromRaw(skArray).get()
  let pk = SkPublicKey.fromRaw(cardPublicKey).get()
  
  let hashFunc = cast[SkEcdhHashFunc](ecdhRawHashFunc)
  let ecdhResultOpt = ecdh[Secp256k1CoordinateSize](sk, pk, hashFunc, nil)
  
  if ecdhResultOpt.isErr:
    raise newException(ValueError, "ECDH computation failed")
  
  result = @(ecdhResultOpt.get())

proc aesCbcEncrypt*(key: seq[byte], iv: seq[byte], plaintext: seq[byte]): seq[byte] =
  ## Encrypt data using AES-256-CBC with ISO/IEC 9797-1 Method 2 padding
  ## 
  ## ISO/IEC 9797-1 Method 2 padding:
  ## - Append 0x80
  ## - Pad with 0x00 until block size (16 bytes)
  
  # Validate key and IV lengths
  if key.len != AesKeySize:
    raise newException(ValueError, "AES-256 requires a " & $AesKeySize & "-byte key, got " & $key.len & " bytes")

  if iv.len != AesBlockSize:
    raise newException(ValueError, "AES CBC requires a " & $AesBlockSize & "-byte IV, got " & $iv.len & " bytes")
  
  var paddedData = plaintext
  paddedData.add(IsoPaddingMarker)
  
  # Pad to block size (16 bytes)
  while paddedData.len mod AesBlockSize != 0:
    paddedData.add(0x00'u8)
  
  # Setup AES context
  var ctx: CBC[aes256]
  var keyArray: array[AesKeySize, byte]
  var ivArray: array[AesBlockSize, byte]
  
  # Copy key and IV to fixed-size arrays
  for i in 0..<AesKeySize:
    keyArray[i] = key[i]
  for i in 0..<AesBlockSize:
    ivArray[i] = iv[i]
  
  # Initialize CBC mode
  ctx.init(keyArray, ivArray)
  
  # Encrypt
  var output = newSeq[byte](paddedData.len)
  ctx.encrypt(paddedData, output)
  ctx.clear()
  
  result = output

proc aesCbcDecrypt*(key: seq[byte], iv: seq[byte], ciphertext: seq[byte]): seq[byte] =
  ## Decrypt data using AES-256-CBC and remove ISO/IEC 9797-1 Method 2 padding
  
  # Validate key and IV lengths
  if key.len != AesKeySize:
    raise newException(ValueError, "AES-256 requires a " & $AesKeySize & "-byte key, got " & $key.len & " bytes")
  if iv.len != AesBlockSize:
    raise newException(ValueError, "AES CBC requires a " & $AesBlockSize & "-byte IV, got " & $iv.len & " bytes")
  
  # Setup AES context
  var ctx: CBC[aes256]
  var keyArray: array[AesKeySize, byte]
  var ivArray: array[AesBlockSize, byte]
  
  # Copy key and IV to fixed-size arrays
  for i in 0..<AesKeySize:
    keyArray[i] = key[i]
  for i in 0..<AesBlockSize:
    ivArray[i] = iv[i]
  
  # Initialize CBC mode
  ctx.init(keyArray, ivArray)
  
  # Decrypt
  var output = newSeq[byte](ciphertext.len)
  ctx.decrypt(ciphertext, output)
  ctx.clear()
  
  # Remove ISO/IEC 9797-1 Method 2 padding
  # Find 0x80 from the end and remove it and everything after
  for i in countdown(output.len - 1, 0):
    if output[i] == IsoPaddingMarker:
      result = output[0..<i]
      return
  
  # If no padding found, this indicates corrupted data or decryption failure
  raise newException(ValueError, "Invalid padding: no " & $IsoPaddingMarker.toHex() & " marker found in decrypted data")


proc generateRandomBytes*(n: int): seq[byte] =
  ## Generate n random bytes using cryptographically secure RNG
  result = newSeq[byte](n)
  if randomBytes(result) != n:
    raise newException(OSError, "Failed to generate random bytes")

proc generatePairingToken*(secret: string): seq[byte] =
  ## Generate a 32-byte pairing token from a secret string using PBKDF2
  ## This matches the standard implementation across all Keycard SDKs
  ##
  ## Uses:
  ## - PBKDF2-HMAC-SHA256
  ## - Salt: "Keycard Pairing Password Salt"
  ## - Iterations: 50000
  ## - Output length: 32 bytes

  const salt = "Keycard Pairing Password Salt"

  var ctx: HMAC[sha256]
  var output: array[Sha256Size, byte]

  # PBKDF2 using SHA256
  discard pbkdf2(ctx, secret, salt, PairingPbkdf2Iterations, output)

  result = @output

proc sha512Hash*(data: seq[byte]): seq[byte] =
  ## Calculate SHA-512 hash of data
  ## Returns 64 bytes
  var ctx: sha512
  ctx.init()
  ctx.update(data)
  let digest = ctx.finish()
  result = @(digest.data)

proc aesCbcMac*(key: seq[byte], data: seq[byte], padding: bool = false): seq[byte] =
  ## Calculate AES CBC-MAC (16 bytes)
  ## Uses zero IV and processes data in CBC mode
  ## Returns the last block of the CBC encryption
  ##
  ## Args:
  ##   key: MAC key (32 bytes)
  ##   data: Data to MAC
  ##   padding: Whether to apply ISO/IEC 9797-1 Method 2 padding (default: false)

  # Validate key length
  if key.len != AesKeySize:
    raise newException(ValueError, "AES-256 requires a " & $AesKeySize & "-byte key, got " & $key.len & " bytes")

  var inputData = data
  
  # Optionally add ISO/IEC 9797-1 Method 2 padding
  if padding:
    inputData.add(IsoPaddingMarker)
    # Pad to block size (16 bytes)
    while inputData.len mod AesBlockSize != 0:
      inputData.add(0x00'u8)

  # Setup AES context with zero IV
  var ctx: CBC[aes256]
  var keyArray: array[AesKeySize, byte]
  var ivArray: array[AesBlockSize, byte]

  # Copy key to fixed-size array
  for i in 0..<AesKeySize:
    keyArray[i] = key[i]

  # Initialize with zero IV
  for i in 0..<AesBlockSize:
    ivArray[i] = 0

  # Initialize CBC mode
  ctx.init(keyArray, ivArray)

  # Encrypt
  var output = newSeq[byte](inputData.len)
  ctx.encrypt(inputData, output)
  ctx.clear()

  # Return last 16 bytes (last block)
  result = output[^AesMacSize..^1]

proc deriveSessionKeys*(sharedSecret: seq[byte], pairingKey: seq[byte], salt: seq[byte]): tuple[encKey: seq[byte], macKey: seq[byte]] =
  ## Derive encryption and MAC keys for secure channel
  ## Concatenates sharedSecret + pairingKey + salt and applies SHA-512
  ## First 32 bytes = encryption key
  ## Last 32 bytes = MAC key

  var combined: seq[byte] = @[]
  combined.add(sharedSecret)
  combined.add(pairingKey)
  combined.add(salt)

  let hash = sha512Hash(combined)

  result.encKey = hash[0..<Sha256Size]
  result.macKey = hash[Sha256Size..<(Sha256Size * 2)]