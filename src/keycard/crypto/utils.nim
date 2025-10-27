## Cryptographic utilities for Keycard operations

import std/strutils
import nimcrypto
import nimcrypto/[bcmode, rijndael, sysrand, pbkdf2, hash]
import secp256k1
import secp256k1/abi
import std/strutils

proc ecdhRawHashFunc(output: pointer, x32: pointer, y32: pointer, data: pointer): cint {.cdecl, noSideEffect, gcsafe.} =
  copyMem(output, x32, 32)
  return 1

proc generateEcdhKeypair*(): tuple[privateKey: seq[byte], publicKey: seq[byte]] =
  ## Generate an ephemeral SECP256K1 keypair for ECDH
  ## Returns (private_key, uncompressed_public_key)
  
  # Generate random 32 bytes for private key
  var privateKeyBytes = newSeq[byte](32)
  if randomBytes(privateKeyBytes) != 32:
    raise newException(OSError, "Failed to generate random bytes")
  
  var skArray: array[32, byte]
  for i in 0..<32:
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
  
  if privateKeyBytes.len != 32:
    raise newException(ValueError, "Private key must be 32 bytes (64 hex chars)")
  
  var skArray: array[32, byte]
  for i in 0..<32:
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
  
  var skArray: array[32, byte]
  for i in 0..<32:
    skArray[i] = privateKey[i]
  
  let sk = SkSecretKey.fromRaw(skArray).get()
  let pk = SkPublicKey.fromRaw(cardPublicKey).get()
  
  let hashFunc = cast[SkEcdhHashFunc](ecdhRawHashFunc)
  let ecdhResultOpt = ecdh[32](sk, pk, hashFunc, nil)
  
  if ecdhResultOpt.isErr:
    raise newException(ValueError, "ECDH computation failed")
  
  result = @(ecdhResultOpt.get())

proc aesCbcEncrypt*(key: seq[byte], iv: seq[byte], plaintext: seq[byte]): seq[byte] =
  ## Encrypt data using AES-256-CBC with ISO/IEC 9797-1 Method 2 padding
  ## 
  ## ISO/IEC 9797-1 Method 2 padding:
  ## - Append 0x80
  ## - Pad with 0x00 until block size (16 bytes)
  
  var paddedData = plaintext
  paddedData.add(0x80'u8)
  
  # Pad to block size (16 bytes)
  while paddedData.len mod 16 != 0:
    paddedData.add(0x00'u8)
  
  # Setup AES context
  var ctx: CBC[aes256]
  var keyArray: array[32, byte]
  var ivArray: array[16, byte]
  
  # Copy key and IV to fixed-size arrays
  for i in 0..<min(32, key.len):
    keyArray[i] = key[i]
  for i in 0..<min(16, iv.len):
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
  
  # Setup AES context
  var ctx: CBC[aes256]
  var keyArray: array[32, byte]
  var ivArray: array[16, byte]
  
  # Copy key and IV to fixed-size arrays
  for i in 0..<min(32, key.len):
    keyArray[i] = key[i]
  for i in 0..<min(16, iv.len):
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
    if output[i] == 0x80:
      result = output[0..<i]
      return
  
  # If no padding found, return as-is
  result = output

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
  const iterations = 50000
  const dklen = 32
  
  var ctx: HMAC[sha256]
  var output: array[32, byte]
  
  # PBKDF2 using SHA256
  discard pbkdf2(ctx, secret, salt, iterations, output)
  
  result = @output