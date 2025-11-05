## Example: Keycard operations
## Usage: nim c -r example/example.nim

import std/strutils
import pcsc/util as putil
import secp256k1
import nimcrypto/sha2
import keycard/transport
import keycard/keycard
import keycard/commands/change_pin
import keycard/commands/init
import keycard/commands/select
import keycard/commands/ident
import keycard/commands/generate_key
import keycard/commands/remove_key
import keycard/commands/load_key
import keycard/commands/generate_mnemonic
import keycard/commands/export_key
import keycard/commands/sign
import keycard/commands/set_pinless_path
import keycard/commands/get_status
import keycard/commands/reset
import keycard/commands/pair
import keycard/commands/open_secure_channel
import keycard/commands/verify_pin
import keycard/commands/unblock_pin
import keycard/commands/unpair
import keycard/commands/store_data
import keycard/commands/get_data

const
  PIN = "123456"
  NEW_PIN = "654321"
  PUK = "234567890123"
  PAIRING_PASSWORD = "KeycardTest"

proc selectCard(card: var Keycard): bool =
  ## Select the Keycard applet and display info
  ## Returns true on success, false on failure
  echo "Selecting card..."
  let selecResult = card.select()

  if selecResult.success:
    echo selecResult.info
    echo "Card public key: ", selecResult.info.publicKey.prettyHex()
    return true
  else:
    echo "SELECT failed!"
    case selecResult.error
    of SelectTransportError:
      echo "  Transport error (connection issue?)"
    of SelectFailed:
      echo "  Card returned error SW: 0x", selecResult.sw.toHex(4)
    else:
      echo "  Unknown error: ", selecResult.error
    return false

proc main() =
  echo "Keycard Example"
  echo "===============\n"
  
  let t = newTransport()
  var card = newKeycard(t)
  
  # List available readers
  echo "Available readers:"
  let readers = card.listReaders()
  if readers.len == 0:
    echo "No readers found!"
    return
  
  for i, reader in readers:
    echo "  [", i, "] ", reader
  
  # Connect to first reader
  echo "\nConnecting to: ", readers[0]
  card.connect(readers[0])
  defer: card.close()
  echo "Connected!\n"
  
  # Initial SELECT
  if not card.selectCard():
    return
  
  # Get public data (before secure channel)
  echo "\nGetting public data (before secure channel)..."
  let getResult = card.getData(PublicData)

  if getResult.success:
    echo "Retrieved ", getResult.data.len, " bytes of public data"
    if getResult.data.len > 0:
      echo "Data: ", getResult.data.prettyHex()
  else:
    echo "Get data failed: ", getResult.error
    if getResult.sw != 0:
      echo "  Status word: 0x", getResult.sw.toHex(4)
    # Continue anyway

  # Identify the card (before init/pairing)
  echo "\nIdentifying card..."
  let identResult = card.ident()

  if identResult.success:
    echo "Card identified successfully!"
    echo "Public key: ", identResult.publicKey.prettyHex()
    echo "Certificate length: ", identResult.certificate.len, " bytes"
    echo "Signature length: ", identResult.signature.len, " bytes"
  else:
    echo "Card identification failed: ", identResult.error
    if identResult.sw != 0:
      echo "  Status word: 0x", identResult.sw.toHex(4)
    # Continue anyway - identification is optional
  
  # Reset if already initialized
  if  card.isInitialized():
    echo "\nCard is already initialized"
    echo "Resetting card..."
    
    let resetResult = card.reset()
    if not resetResult.success:
      echo "Reset failed SW: 0x", resetResult.sw.toHex(4)
      return
    
    echo "Card reset successfully\n"
    
    # Select again after reset (card state is cleared by reset)
    if not card.selectCard():
      return

  # Initialize the card
  echo "\nInitializing card..."

  let initResult = card.init(
    pin = PIN,
    puk = PUK,
    pairingSecret = PAIRING_PASSWORD
  )

  if not initResult.success:
    echo "Initialization failed: ", initResult.error
    if initResult.sw != 0:
      echo "  Status word: 0x", initResult.sw.toHex(4)
    return

  echo "Card initialized successfully\n"

  # Select again to see initialized state
  if not card.selectCard():
    return

  # Check if card supports secure channel
  if not card.hasSecureChannel():
    echo "\nCard does not support secure channel!"
    echo "All operations completed successfully!"
    return

  echo "\nCard supports secure channel"

  # Pair with the card (two-step mutual authentication)
  echo "\nPairing with card..."

  let pairResult = card.pair(PAIRING_PASSWORD)

  if not pairResult.success:
    echo "Failed to pair: ", pairResult.error
    if pairResult.sw != 0:
      echo "  Status word: 0x", pairResult.sw.toHex(4)
    return

  echo "Pairing successful!"
  echo "Assigned pairing index: ", pairResult.pairingIndex
  echo "Pairing key: ", pairResult.pairingKey.prettyHex()
  echo "Salt: ", pairResult.salt.prettyHex()

  # Open secure channel
  echo "\nOpening secure channel..."
  echo "Using pairing index: ", pairResult.pairingIndex

  let openResult = card.openSecureChannel(pairResult.pairingIndex, pairResult.pairingKey)

  if not openResult.success:
    echo "Failed to open secure channel: ", openResult.error
    if openResult.sw != 0:
      echo "  Status word: 0x", openResult.sw.toHex(4)
    return

  echo "Secure channel opened successfully!"
  echo "Salt: ", openResult.salt.prettyHex()
  echo "IV: ", openResult.iv.prettyHex()
  echo "Encryption key: ", card.secureChannel.encryptionKey.prettyHex()
  echo "MAC key: ", card.secureChannel.macKey.prettyHex()

  echo "\n  Secure channel is now open!"
  echo "  All subsequent commands can be encrypted"
  echo "  Channel remains open until card is deselected or reset"

  # Get application status
  echo "\nGetting application status..."
  let statusResult = card.getStatus()

  if statusResult.success:
    echo "Application status retrieved successfully!"
    echo "PIN retry count: ", statusResult.appStatus.pinRetryCount
    echo "PUK retry count: ", statusResult.appStatus.pukRetryCount
    echo "Key initialized: ", statusResult.appStatus.keyInitialized
  else:
    echo "Get status failed: ", statusResult.error
    if statusResult.sw != 0:
      echo "  Status word: 0x", statusResult.sw.toHex(4)
    # Continue anyway
  
  # Verify PIN
  echo "\nVerifying PIN..."

  let verifyResult = card.verifyPin(PIN)

  if verifyResult.success:
    echo "PIN verified successfully!"
    echo "PIN is now authenticated for this session"
    echo "Session remains authenticated until card is deselected or reset"
  else:
    echo "PIN verification failed: ", verifyResult.error
    if verifyResult.sw != 0:
      echo "  Status word: 0x", verifyResult.sw.toHex(4)

    case verifyResult.error
    of VerifyPinBlocked:
      echo "  PIN is BLOCKED! Use PUK to unblock"
    of VerifyPinIncorrect:
      echo "  Wrong PIN! Retries remaining: ", verifyResult.retriesRemaining
    of VerifyPinChannelNotOpen:
      echo "  Secure channel is not open"
    of VerifyPinSecureApduError:
      echo "  Secure APDU encryption/MAC error"
    of VerifyPinTransportError:
      echo "  Transport/connection error"
    else:
      discard
    return
  
  # Change PIN (demonstrate CHANGE PIN command)
  echo "\nChanging PIN from ", PIN, " to ", NEW_PIN, "..."

  # Convert PIN string to bytes
  var newPinBytes: seq[byte] = @[]
  for c in NEW_PIN:
    newPinBytes.add(byte(c))

  let changePinResult = card.changePin(UserPin, newPinBytes)

  if changePinResult.success:
    echo "PIN changed successfully!"
    echo "New PIN is now authenticated for this session"
    echo "Note: In production, you'd use the new PIN for future sessions"
  else:
    echo "Change PIN failed: ", changePinResult.error
    if changePinResult.sw != 0:
      echo "  Status word: 0x", changePinResult.sw.toHex(4)

    case changePinResult.error
    of ChangePinInvalidFormat:
      echo "  (Invalid PIN format - must be 6 digits)"
    of ChangePinInvalidP1:
      echo "  (Invalid PIN type)"
    of ChangePinCapabilityNotSupported:
      echo "  (Card does not support credentials management)"
    of ChangePinConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified)"
    of ChangePinChannelNotOpen:
      echo "  (Secure channel is not open)"
    of ChangePinSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of ChangePinTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  # Demonstrate PIN blocking and unblocking
  echo "\nDemonstrating PIN blocking by attempting to verify with old PIN..."
  echo "Attempting to verify with old PIN (", PIN, ") - should fail 3 times to block PIN"

  # Try old PIN 3 times to block it
  for i in 1..3:
    echo "\nAttempt ", i, " with old PIN..."
    let blockResult = card.verifyPin("111111")
    echo blockResult.success
    if not blockResult.success:
      if blockResult.error == VerifyPinIncorrect:
        echo "  Wrong PIN! Retries remaining: ", blockResult.retriesRemaining
      elif blockResult.error == VerifyPinBlocked:
        echo "  PIN is now BLOCKED!"
        break
      else:
        echo "  Verify failed: ", blockResult.error

  # Now unblock with PUK
  echo "\nUnblocking PIN with PUK and setting it back to original..."
  let unblockResult = card.unblockPin(PUK, PIN)

  if unblockResult.success:
    echo "PIN unblocked successfully!"
    echo "PIN has been reset to ", PIN, " and is now authenticated for this session"
  else:
    echo "Unblock PIN failed: ", unblockResult.error
    if unblockResult.sw != 0:
      echo "  Status word: 0x", unblockResult.sw.toHex(4)

    case unblockResult.error
    of UnblockPinWrongPuk:
      echo "  (Wrong PUK! Retries remaining: ", unblockResult.retriesRemaining, ")"
    of UnblockPinBlocked:
      echo "  (PUK is blocked! Wallet is lost)"
    of UnblockPinInvalidFormat:
      echo "  (Invalid format - PUK must be 12 digits, PIN must be 6 digits)"
    of UnblockPinCapabilityNotSupported:
      echo "  (Card does not support credentials management)"
    of UnblockPinChannelNotOpen:
      echo "  (Secure channel is not open)"
    of UnblockPinSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of UnblockPinTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    return

  # Note: PIN is now back to original value via unblock
  
  # Generate key on card (demonstrate GENERATE KEY command)
  echo "\nGenerating key on card..."
  let generateResult = card.generateKey()

  if generateResult.success:
    echo "Key generated successfully!"
    echo "Key UID (SHA-256 of public key): ", generateResult.keyUID.prettyHex()
    echo "Note: The card state is now the same as if LOAD KEY was performed"
  else:
    echo "Generate key failed: ", generateResult.error
    if generateResult.sw != 0:
      echo "  Status word: 0x", generateResult.sw.toHex(4)

    case generateResult.error
    of GenerateKeyCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of GenerateKeyConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified)"
    of GenerateKeyChannelNotOpen:
      echo "  (Secure channel is not open)"
    of GenerateKeySecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of GenerateKeyTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    return

  # Generate a mnemonic (demonstrate GENERATE MNEMONIC command)
  echo "\n========================================"
  echo "GENERATE MNEMONIC DEMO"
  echo "========================================"
  echo "\nGenerating a BIP39 mnemonic (12 words)..."

  let mnemonicResult = card.generateMnemonic(checksumSize = 4)

  if mnemonicResult.success:
    echo "Mnemonic generated successfully!"
    echo "Number of words: ", mnemonicResult.indexes.len
    echo "Word indexes (0-2047): ", mnemonicResult.indexes
    echo ""
    echo "Note: These are word indexes (0-2047) for the BIP39 wordlist"
    echo "      In a real application, you would convert these to actual words"
    echo "      using the official BIP39 English wordlist"
  else:
    echo "Generate mnemonic failed: ", mnemonicResult.error
    if mnemonicResult.sw != 0:
      echo "  Status word: 0x", mnemonicResult.sw.toHex(4)

    case mnemonicResult.error
    of GenerateMnemonicCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of GenerateMnemonicInvalidChecksumSize:
      echo "  (Invalid checksum size - must be 4-8)"
    of GenerateMnemonicChannelNotOpen:
      echo "  (Secure channel is not open)"
    of GenerateMnemonicSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of GenerateMnemonicTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  echo "\n========================================"

  # Export the current key (demonstrate EXPORT KEY command)
  echo "\nExporting current key (public key only)..."
  let exportResult = card.exportKey(CurrentKey, PublicOnly)

  if exportResult.success:
    echo "Key exported successfully!"
    if exportResult.publicKey.len > 0:
      echo "Public key (", exportResult.publicKey.len, " bytes): ", exportResult.publicKey.prettyHex()
    if exportResult.privateKey.len > 0:
      echo "Private key (", exportResult.privateKey.len, " bytes): [REDACTED]"
    if exportResult.chainCode.len > 0:
      echo "Chain code (", exportResult.chainCode.len, " bytes): ", exportResult.chainCode.prettyHex()
  else:
    echo "Export key failed: ", exportResult.error
    if exportResult.sw != 0:
      echo "  Status word: 0x", exportResult.sw.toHex(4)

    case exportResult.error
    of ExportKeyCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of ExportKeyPrivateNotExportable:
      echo "  (Private key cannot be exported for this path)"
    of ExportKeyInvalidPath:
      echo "  (Path is malformed)"
    of ExportKeyInvalidParams:
      echo "  (Invalid P1 or P2 parameters)"
    of ExportKeyConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified)"
    of ExportKeyChannelNotOpen:
      echo "  (Secure channel is not open)"
    of ExportKeySecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of ExportKeyTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  # Sign some data and verify signature (demonstrate SIGN command)
  echo "\n========================================"
  echo "SIGNING AND VERIFICATION DEMO"
  echo "========================================"

  # Create a message and hash it
  let message = "Hello, Keycard! This is a test message for signing."
  echo "\nMessage to sign: \"", message, "\""

  # Calculate SHA-256 hash of the message
  var messageBytes: seq[byte] = @[]
  for c in message:
    messageBytes.add(byte(c))

  let hashDigest = sha256.digest(messageBytes)
  var hash: array[32, byte]
  for i in 0..<32:
    hash[i] = hashDigest.data[i]

  echo "Message hash (SHA-256): ", hash.prettyHex()

  # Sign the hash with the current key
  echo "\nSigning with current key on card..."
  let signResult = card.sign(hash)

  if not signResult.success:
    echo "Sign failed: ", signResult.error
    if signResult.sw != 0:
      echo "  Status word: 0x", signResult.sw.toHex(4)

    case signResult.error
    of SignCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of SignDataTooShort:
      echo "  (Hash must be exactly 32 bytes)"
    of SignNoPinlessPath:
      echo "  (No PIN-less path defined)"
    of SignAlgorithmNotSupported:
      echo "  (Algorithm not supported - only ECDSA secp256k1 on Keycard)"
    of SignConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified and key loaded)"
    of SignChannelNotOpen:
      echo "  (Secure channel is not open)"
    of SignSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of SignTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway - skip verification
  else:
    echo "Signature created successfully!"
    echo "Signature (", signResult.signature.len, " bytes): ", signResult.signature.prettyHex()

    # If we got the signature template format, we have the public key
    if signResult.publicKey.len > 0:
      echo "Public key from signature template: ", signResult.publicKey.prettyHex()

    # Now export the public key to verify the signature
    echo "\nExporting public key for verification..."
    let verifyExportResult = card.exportKey(CurrentKey, PublicOnly)

    if not verifyExportResult.success:
      echo "Export key for verification failed: ", verifyExportResult.error
      # Continue anyway
    elif verifyExportResult.publicKey.len == 0:
      echo "No public key returned from export"
      # Continue anyway
    else:
      echo "Public key exported (", verifyExportResult.publicKey.len, " bytes)"

      # Verify the signature
      echo "\nVerifying signature..."

      try:
        # Parse the signature
        # If signature is 65 bytes, it includes recovery ID: (r, s, recId)
        # If signature is 64 bytes, it's just (r, s)
        var sigToVerify: seq[byte]
        var pubKeyToUse: seq[byte] = verifyExportResult.publicKey

        if signResult.signature.len == 65:
          # Signature with recovery ID - extract just r and s for verification
          sigToVerify = signResult.signature[0..63]
          echo "Using 65-byte signature format (r, s, recId)"
          echo "Recovery ID: ", signResult.signature[64]
        elif signResult.signature.len == 64:
          # Signature without recovery ID
          sigToVerify = signResult.signature
          echo "Using 64-byte signature format (r, s)"
        else:
          echo "Unexpected signature length: ", signResult.signature.len
          sigToVerify = signResult.signature

        # Verify using secp256k1
        # Parse public key (assuming uncompressed format: 0x04 + X + Y)
        if pubKeyToUse[0] == 0x04 and pubKeyToUse.len == 65:
          # Uncompressed public key
          let pubKeyResult = SkPublicKey.fromRaw(pubKeyToUse)
          if pubKeyResult.isOk:
            let pubKey = pubKeyResult.get()
 
            # Parse signature (64 bytes: r + s)
            if sigToVerify.len == 64:
              # Try to parse as raw signature
              let sigResult = SkSignature.fromRaw(sigToVerify)
              if sigResult.isOk:
                let sig = sigResult.get()
 
                # Create message from hash
                var hashArray: array[32, byte]
                for i in 0..<32:
                  hashArray[i] = hash[i]
 
                let msgResult = SkMessage.fromBytes(hashArray)
                if msgResult.isOk:
                  let msg = msgResult.get()
 
                  # Verify signature
                  if verify(sig, msg, pubKey):
                    echo "  SIGNATURE VERIFICATION SUCCESSFUL!"
                    echo "  The signature is valid for the message"
                    echo "  The key on the card correctly signed the hash"
                  else:
                    echo "  SIGNATURE VERIFICATION FAILED!"
                    echo "  The signature is NOT valid for this message"
                else:
                  echo "Failed to create message from hash"
              else:
                echo "Failed to parse signature (raw format)"
            else:
              echo "Cannot verify: signature has unexpected length ", sigToVerify.len
          else:
            echo "Failed to parse public key"
        else:
          echo "Unexpected public key format (expected uncompressed 0x04 + 64 bytes)"
          echo "Public key length: ", pubKeyToUse.len
          if pubKeyToUse.len > 0:
            echo "First byte: 0x", pubKeyToUse[0].toHex(2)
      except Exception as e:
        echo "Exception during verification: ", e.msg

  echo "\n========================================"

  # Set PIN-less path (demonstrate SET PINLESS PATH command)
  echo "\n========================================"
  echo "SET PINLESS PATH DEMO"
  echo "========================================"

  # Set a PIN-less path that allows signing without PIN when current key matches
  let pinlessPath = "m/44'/60'/0'/0/0"
  echo "\nSetting PIN-less path: ", pinlessPath
  echo "This allows signing without PIN verification when the current key matches this path"

  let setPinlessResult = card.setPinlessPath(pinlessPath)

  if setPinlessResult.success:
    echo "PIN-less path set successfully!"
    echo "Note: Signing with SIGN command using SignPinlessPath derivation option"
    echo "      will now work without PIN verification when on this path"
  else:
    echo "Set PIN-less path failed: ", setPinlessResult.error
    if setPinlessResult.sw != 0:
      echo "  Status word: 0x", setPinlessResult.sw.toHex(4)

    case setPinlessResult.error
    of SetPinlessPathInvalidData:
      echo "  (Invalid path data)"
    of SetPinlessPathConditionsNotMet:
      echo "  (PIN must be verified)"
    of SetPinlessPathChannelNotOpen:
      echo "  (Secure channel is not open)"
    of SetPinlessPathSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of SetPinlessPathTransportError:
      echo "  (Transport/connection error)"
    else:
      discard

  # Demonstrate disabling PIN-less path
  echo "\nDisabling PIN-less path (setting to empty)..."
  let disablePinlessResult = card.setPinlessPath("")

  if disablePinlessResult.success:
    echo "PIN-less path disabled successfully!"
    echo "Signing will now require PIN verification again"
  else:
    echo "Disable PIN-less path failed: ", disablePinlessResult.error

  echo "\n========================================"

  # Store some data
  echo "\nStoring public data..."
  let testString = "Hello Keycard!"
  var dataToStore: seq[byte] = @[]
  for c in testString:
    dataToStore.add(byte(c))

  let storeResult = card.storeData(PublicData, dataToStore)

  if storeResult.success:
    echo "Data stored successfully!"
    echo "Stored ", dataToStore.len, " bytes of public data"
  else:
    echo "Store data failed: ", storeResult.error
    if storeResult.sw != 0:
      echo "  Status word: 0x", storeResult.sw.toHex(4)

    case storeResult.error
    of StoreDataTooLong:
      echo "  (Data is too long)"
    of StoreDataUndefinedP1:
      echo "  (Undefined data type)"
    of StoreDataCapabilityNotSupported:
      echo "  (Card does not support this data type - NDEF capability required)"
    of StoreDataSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of StoreDataChannelNotOpen:
      echo "  (Secure channel is not open)"
    of StoreDataTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  # Remove key from card (demonstrate REMOVE KEY command)
  echo "\nRemoving key from card..."
  let removeResult = card.removeKey()
 
  if removeResult.success:
    echo "Key removed successfully!"
    echo "Card is now in an uninitialized state"
    echo "No signing operation is possible until a new LOAD KEY command"
  else:
    echo "Remove key failed: ", removeResult.error
    if removeResult.sw != 0:
      echo "  Status word: 0x", removeResult.sw.toHex(4)
 
    case removeResult.error
    of RemoveKeyCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of RemoveKeyConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified)"
    of RemoveKeyChannelNotOpen:
      echo "  (Secure channel is not open)"
    of RemoveKeySecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of RemoveKeyTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  # Load a key onto the card (demonstrate LOAD KEY command)
  echo "\n========================================"
  echo "LOAD KEY DEMO"
  echo "========================================"
  echo "\nLoading a keypair onto the card..."
  echo "Note: This is just a demo with a test key - never use this key in production!"

  # Create a test keypair (in real usage, you'd use a properly generated key)
  # This is a dummy private key (32 bytes) - DO NOT USE IN PRODUCTION
  let testPrivateKey = @[
    byte(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
  ]

  # Load the keypair (public key can be omitted - card will derive it)
  let loadResult = card.loadKey(EccKeypair, testPrivateKey)

  if loadResult.success:
    echo "Key loaded successfully!"
    echo "Key UID (SHA-256 of public key): ", loadResult.keyUID.prettyHex()
    echo "The card can now perform signing operations with this key"
  else:
    echo "Load key failed: ", loadResult.error
    if loadResult.sw != 0:
      echo "  Status word: 0x", loadResult.sw.toHex(4)

    case loadResult.error
    of LoadKeyCapabilityNotSupported:
      echo "  (Card does not support key management)"
    of LoadKeyInvalidFormat:
      echo "  (Invalid key format)"
    of LoadKeyInvalidKeyType:
      echo "  (Invalid key type - P1 parameter)"
    of LoadKeyConditionsNotMet:
      echo "  (Conditions not met - PIN must be verified)"
    of LoadKeyChannelNotOpen:
      echo "  (Secure channel is not open)"
    of LoadKeySecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of LoadKeyTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    # Continue anyway

  echo "\n========================================"

  # Unpair the pairing slot
  echo "\nUnpairing slot ", pairResult.pairingIndex, "..."

  let unpairResult = card.unpair(pairResult.pairingIndex)

  if unpairResult.success:
    echo "Unpaired successfully!"
    echo "Pairing slot ", pairResult.pairingIndex, " is now free"
  else:
    echo "Unpair failed: ", unpairResult.error
    if unpairResult.sw != 0:
      echo "  Status word: 0x", unpairResult.sw.toHex(4)

    case unpairResult.error
    of UnpairSecurityConditionsNotMet:
      echo "  (Security conditions not met)"
    of UnpairInvalidIndex:
      echo "  (Invalid pairing index)"
    of UnpairSecureApduError:
      echo "  (Secure APDU encryption/MAC error)"
    of UnpairChannelNotOpen:
      echo "  (Secure channel is not open)"
    of UnpairTransportError:
      echo "  (Transport/connection error)"
    else:
      discard
    return

  echo "\nAll operations completed successfully!"

when isMainModule:
  main()