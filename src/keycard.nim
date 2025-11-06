## Keycard SDK for Nim
## High-level interface for interacting with Status Keycard
##
## This is a convenience module that re-exports all commonly used types and commands.
## You can import this for quick access to everything:
##   import keycard
##
## Or import specific modules for better compilation performance:
##   import keycard/keycard
##   import keycard/commands/select
##   import keycard/commands/verify_pin

import keycard/keycard
import keycard/transport
import keycard/apdu
import keycard/constants
import keycard/types/application_info
import keycard/commands/select
import keycard/commands/change_pin
import keycard/commands/export_key
import keycard/commands/generate_key
import keycard/commands/remove_key
import keycard/commands/get_data
import keycard/commands/get_status
import keycard/commands/ident
import keycard/commands/init
import keycard/commands/reset
import keycard/commands/pair
import keycard/commands/open_secure_channel
import keycard/commands/mutually_authenticate
import keycard/commands/verify_pin
import keycard/commands/unblock_pin
import keycard/commands/unpair
import keycard/commands/sign
import keycard/commands/store_data
import keycard/secure_apdu
import keycard/commands/load_key
import keycard/commands/generate_mnemonic
import keycard/commands/set_pinless_path

export keycard
export transport
export apdu
export constants
export application_info
export select
export change_pin
export export_key
export generate_key
export remove_key
export get_data
export get_status
export ident
export init
export reset
export pair
export open_secure_channel
export mutually_authenticate
export verify_pin
export unblock_pin
export unpair
export sign
export store_data
export secure_apdu
export load_key
export generate_mnemonic
export set_pinless_path
