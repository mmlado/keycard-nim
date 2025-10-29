## High-level Keycard interface
## Manages card state and provides command interface
##
## To use commands, import them explicitly:
##   import keycard/commands/init
##   import keycard/commands/select
##   import keycard/commands/pair
##   import keycard/commands/verify_pin
##   ... etc

import transport
import types/application_info

export transport
export application_info

type
  SecureChannel* = object
    open*: bool
    encryptionKey*: seq[byte]
    macKey*: seq[byte]
    iv*: seq[byte]
    pairingIndex*: byte

  Keycard* = object
    transport*: Transport
    publicKey*: seq[byte]
    selected*: bool
    appInfo*: ApplicationInfo
    secureChannel*: SecureChannel

proc newKeycard*(transport: Transport): Keycard =
  ## Create a new Keycard interface with the given transport
  Keycard(transport: transport, selected: false)

proc connect*(card: var Keycard, reader: string) =
  ## Connect to a specific card reader
  card.transport.connect(reader)

proc close*(card: var Keycard) =
  ## Close the connection to the card
  card.transport.close()

proc listReaders*(card: Keycard): seq[string] =
  ## List available card readers
  card.transport.listReaders()

proc isInitialized*(card: Keycard): bool =
  ## Check if card has been selected and is initialized
  card.appInfo.isInitialized()

proc hasSecureChannel*(card: Keycard): bool =
  ## Check if card supports secure channel (only valid after select)
  card.appInfo.hasSecureChannel()

proc version*(card: Keycard): tuple[major, minor: byte] =
  ## Get application version (only valid after select)
  card.appInfo.appVersion

proc isSecureChannelOpen*(card: Keycard): bool =
  ## Check if secure channel is currently open
  card.secureChannel.open