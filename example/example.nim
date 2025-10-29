## Example: Keycard operations
## Usage: nim c -r example/example.nim

import std/strutils
import pcsc/util as putil
import keycard/transport
import keycard/keycard
import keycard/commands/init
import keycard/commands/select
import keycard/commands/reset
import keycard/commands/pair
import keycard/commands/open_secure_channel
import keycard/commands/mutually_authenticate
import keycard/commands/verify_pin
import keycard/secure_apdu
import keycard/crypto/utils
import keycard/util

const
  PIN = "123456"
  PUK = "123456123456"
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

  echo "\nAll operations completed successfully!"

when isMainModule:
  main()