## Example: Keycard operations
## Usage: nim c -r example/example.nim

import std/strutils
import pcsc/util as putil
import keycard/transport
import keycard/keycard
import keycard/commands/change_pin
import keycard/commands/init
import keycard/commands/select
import keycard/commands/ident
import keycard/commands/generate_key
import keycard/commands/get_status
import keycard/commands/reset
import keycard/commands/pair
import keycard/commands/open_secure_channel
import keycard/commands/mutually_authenticate
import keycard/commands/verify_pin
import keycard/commands/unblock_pin
import keycard/commands/unpair
import keycard/commands/store_data
import keycard/commands/get_data
import keycard/secure_apdu
import keycard/crypto/utils
import keycard/util

const
  PIN = "123456"
  NEW_PIN = "654321"
  PUK = "234567890123"
  PAIRING_PASSWORD = "KeycardTest"

proc selectCard(card: var Keycard): bool =
  ## Select the Keycard applet and display info
  ## Returns true on success, false on failure
  echo "Selecting card..."
  let result = card.select()

  if result.success:
    echo result.info
    echo "Card public key: ", result.info.publicKey.prettyHex()
    return true
  else:
    echo "SELECT failed!"
    case result.error
    of SelectTransportError:
      echo "  Transport error (connection issue?)"
    of SelectFailed:
      echo "  Card returned error SW: 0x", result.sw.toHex(4)
    else:
      echo "  Unknown error: ", result.error
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