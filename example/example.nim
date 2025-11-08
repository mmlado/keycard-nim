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

template checkResult(result: untyped, operation: string) =
  ## Check if result is successful, exit with error if not
  if not result.success:
    echo operation, " failed: ", result.error
    when compiles(result.sw):
      if result.sw != 0:
        echo "  Status word: 0x", result.sw.toHex(4)
    when compiles(result.retriesRemaining):
      echo "  Retries remaining: ", result.retriesRemaining
    quit(1)

proc printSectionHeader(title: string) =
  ## Print a section header with separators
  echo "\n========================================"
  echo title
  echo "========================================"
 
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
  printSectionHeader("GET DATA DEMO")
  let getResult = card.getData(PublicData)
  checkResult(getResult, "Get data")

  echo "Retrieved ", getResult.data.len, " bytes of public data"
  if getResult.data.len > 0:
    echo "Data: ", getResult.data.prettyHex()

  printSectionHeader("IDENTIFY CARD DEMO")
  let identResult = card.ident()
  checkResult(identResult, "Card identification")

  echo "Card identified successfully!"
  echo "Public key: ", identResult.publicKey.prettyHex()
  echo "Certificate length: ", identResult.certificate.len, " bytes"
  echo "Signature length: ", identResult.signature.len, " bytes"
  
  # Reset if already initialized
  if  card.isInitialized():
    printSectionHeader("RESET CARD DEMO")
    echo "\nCard is already initialized"
    echo "Resetting card..."

    let resetResult = card.reset()
    checkResult(resetResult, "Reset")

    echo "Card reset successfully\n"
    
    # Select again after reset (card state is cleared by reset)
    if not card.selectCard():
      return

  printSectionHeader("INITIALIZE CARD DEMO")

  let initResult = card.init(
    pin = PIN,
    puk = PUK,
    pairingSecret = PAIRING_PASSWORD
  )
  checkResult(initResult, "Initialization")

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
  printSectionHeader("PAIR DEMO")

  let pairResult = card.pair(PAIRING_PASSWORD)
  checkResult(pairResult, "Pairing")

  echo "Pairing successful!"
  echo "Assigned pairing index: ", pairResult.pairingIndex
  echo "Pairing key: ", pairResult.pairingKey.prettyHex()
  echo "Salt: ", pairResult.salt.prettyHex()

  printSectionHeader("OPEN SECURE CHANNEL DEMO")
  echo "Using pairing index: ", pairResult.pairingIndex

  let openResult = card.openSecureChannel(pairResult.pairingIndex, pairResult.pairingKey)
  checkResult(openResult, "Open secure channel")

  echo "Secure channel opened successfully!"
  echo "Salt: ", openResult.salt.prettyHex()
  echo "IV: ", openResult.iv.prettyHex()
  echo "Encryption key: ", card.secureChannel.encryptionKey.prettyHex()
  echo "MAC key: ", card.secureChannel.macKey.prettyHex()

  echo "\n  Secure channel is now open!"
  echo "  All subsequent commands can be encrypted"
  echo "  Channel remains open until card is deselected or reset"

  printSectionHeader("GET STATUS DEMO")
  let statusResult = card.getStatus()
  checkResult(statusResult, "Get status")

  echo "Application status retrieved successfully!"
  echo "PIN retry count: ", statusResult.appStatus.pinRetryCount
  echo "PUK retry count: ", statusResult.appStatus.pukRetryCount
  echo "Key initialized: ", statusResult.appStatus.keyInitialized
  
  printSectionHeader("VERIFY PIN DEMO")

  let verifyResult = card.verifyPin(PIN)
  checkResult(verifyResult, "Verify PIN")

  echo "PIN verified successfully!"
  echo "PIN is now authenticated for this session"
  echo "Session remains authenticated until card is deselected or reset"
  
  printSectionHeader("CHANGE PIN DEMO")
  echo "\nChanging PIN from ", PIN, " to ", NEW_PIN, "..."

  let changePinResult = card.changePin(UserPin, NEW_PIN)
  checkResult(changePinResult, "Change PIN")

  echo "PIN changed successfully!"
  echo "New PIN is now authenticated for this session"
  echo "Note: In production, you'd use the new PIN for future sessions"

  printSectionHeader("PIN BLOCKING AND UNBLOCKING DEMO")
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
  checkResult(unblockResult, "Unblock PIN")

  echo "PIN unblocked successfully!"
  echo "PIN has been reset to ", PIN, " and is now authenticated for this session"

  # Note: PIN is now back to original value via unblock
  
  printSectionHeader("GENERATE KEY DEMO")
  let generateResult = card.generateKey()
  checkResult(generateResult, "Generate key")

  echo "Key generated successfully!"
  echo "Key UID (SHA-256 of public key): ", generateResult.keyUID.prettyHex()
  echo "Note: The card state is now the same as if LOAD KEY was performed"

  # Generate a mnemonic (demonstrate GENERATE MNEMONIC command)
  printSectionHeader("GENERATE MNEMONIC DEMO")
  echo "\nGenerating a BIP39 mnemonic (12 words)..."

  let mnemonicResult = card.generateMnemonic(checksumSize = 4)
  checkResult(mnemonicResult, "Generate mnemonic")

  echo "Mnemonic generated successfully!"
  echo "Number of words: ", mnemonicResult.indexes.len
  echo "Word indexes (0-2047): ", mnemonicResult.indexes
  echo ""
  echo "Note: These are word indexes (0-2047) for the BIP39 wordlist"
  echo "      In a real application, you would convert these to actual words"
  echo "      using the official BIP39 English wordlist"

  echo "\n========================================"

  printSectionHeader("EXPORT KEY DEMO")
  let exportResult = card.exportKey(CurrentKey, PublicOnly)
  checkResult(exportResult, "Export key")

  echo "Key exported successfully!"
  if exportResult.publicKey.len > 0:
    echo "Public key (", exportResult.publicKey.len, " bytes): ", exportResult.publicKey.prettyHex()
  if exportResult.privateKey.len > 0:
    echo "Private key (", exportResult.privateKey.len, " bytes): [REDACTED]"
  if exportResult.chainCode.len > 0:
    echo "Chain code (", exportResult.chainCode.len, " bytes): ", exportResult.chainCode.prettyHex()

  printSectionHeader("SIGNING AND VERIFICATION DEMO")

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
  checkResult(signResult, "Sign")

  echo "Signature created successfully!"
  echo "Signature (", signResult.signature.len, " bytes): ", signResult.signature.prettyHex()

  # If we got the signature template format, we have the public key
  if signResult.publicKey.len > 0:
    echo "Public key from signature template: ", signResult.publicKey.prettyHex()

  # Now export the public key to verify the signature
  echo "\nExporting public key for verification..."
  let verifyExportResult = card.exportKey(CurrentKey, PublicOnly)
  checkResult(verifyExportResult, "Export key for verification")

  if verifyExportResult.publicKey.len == 0:
    echo "No public key returned from export"
    quit(1)

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

  # Set PIN-less path (demonstrate SET PINLESS PATH command)
  printSectionHeader("SET PINLESS PATH DEMO")

  # Set a PIN-less path that allows signing without PIN when current key matches
  let pinlessPath = "m/44'/60'/0'/0/0"
  echo "\nSetting PIN-less path: ", pinlessPath
  echo "This allows signing without PIN verification when the current key matches this path"

  let setPinlessResult = card.setPinlessPath(pinlessPath)
  checkResult(setPinlessResult, "Set PIN-less path")

  echo "PIN-less path set successfully!"
  echo "Note: Signing with SIGN command using SignPinlessPath derivation option"
  echo "      will now work without PIN verification when on this path"

  # Demonstrate disabling PIN-less path
  echo "\nDisabling PIN-less path (setting to empty)..."
  let disablePinlessResult = card.setPinlessPath("")
  checkResult(disablePinlessResult, "Disable PIN-less path")

  echo "PIN-less path disabled successfully!"
  echo "Signing will now require PIN verification again"

  printSectionHeader("STORE DATA DEMO")
  let testString = "Hello Keycard!"
  var dataToStore: seq[byte] = @[]
  for c in testString:
    dataToStore.add(byte(c))

  let storeResult = card.storeData(PublicData, dataToStore)
  checkResult(storeResult, "Store data")

  echo "Data stored successfully!"
  echo "Stored ", dataToStore.len, " bytes of public data"

  printSectionHeader("REMOVE KEY DEMO")
  let removeResult = card.removeKey()
  checkResult(removeResult, "Remove key")

  echo "Key removed successfully!"
  echo "Card is now in an uninitialized state"
  echo "No signing operation is possible until a new LOAD KEY command"

  printSectionHeader("LOAD KEY DEMO")
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
  checkResult(loadResult, "Load key")

  echo "Key loaded successfully!"
  echo "Key UID (SHA-256 of public key): ", loadResult.keyUID.prettyHex()
  echo "The card can now perform signing operations with this key"

  printSectionHeader("UNPAIR DEMO")
  echo "\nUnpairing slot ", pairResult.pairingIndex, "..."

  let unpairResult = card.unpair(pairResult.pairingIndex)
  checkResult(unpairResult, "Unpair")

  echo "Unpaired successfully!"
  echo "Pairing slot ", pairResult.pairingIndex, " is now free"

  echo "\nAll operations completed successfully!"

when isMainModule:
  main()