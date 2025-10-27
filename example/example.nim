## Example: Keycard operations
## Usage: nim c -r examples/example.nim

import std/strutils
import pcsc/util as putil
import keycard/transport
import keycard/keycard
import keycard/commands/init
import keycard/commands/select
import keycard/commands/reset

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
  
  echo "\nAll operations completed successfully!"

when isMainModule:
  main()