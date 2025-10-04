## Example: SELECT command on a real Keycard
## 
## Usage: nim c -r examples/select_example.nim

import std/strutils
import pcsc/util as putil
import keycard/transport
import keycard/keycard
import keycard/commands/select
import keycard/constants

proc main() =
  echo "Keycard Example"
  echo "=====================\n"
  
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
  
  # Send SELECT command
  echo "Sending SELECT command..."
  echo "  AID: ", KeycardAid.prettyHex()
  
  let result = card.select()
  
  if result.success:
    echo result.info
    
    if card.isInitialized():
      echo "Card is initialized"
    
    if card.hasSecureChannel():
      echo "Supports secure channel"
    
    let (major, minor) = card.version()
    echo "Version: ", major, ".", minor
    
    echo card.appInfo.instanceUid.toHex()
  else:
    echo "\n✗ SELECT failed!"
    case result.error
    of SelectTransportError:
      echo "  Transport error (connection issue?)"
    of SelectFailed:
      echo "  Card returned error SW: 0x", result.sw.toHex(4)
    else:
      echo "  Unknown error: ", result.error

when isMainModule:
  main()