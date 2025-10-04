# keycard-nim

A Nim SDK to interact with the [Status Keycard](https://keycard.tech) - a hardware wallet implementation on JavaCard.

## Features

- 🔒 Secure communication with Keycard hardware wallets
- 🧪 Mock PC/SC implementation for testing without hardware
- ✅ Idiomatic Nim with Result types instead of exceptions
- 🎯 Type-safe APDU construction
- 📦 Modular architecture with clean separation of concerns

## Installation

```bash
git clone https://github.com/mmlado/keycard-nim.git
cd keycard-nim
nimble install
```

## Dependencies

- [pcsc-nim](https://github.com/mmlado/pcsc-nim) - PC/SC library for smart card access
- Nim >= 1.6.14

## Quick Start

```nim
import keycard/keycard
import keycard/commands/select
import keycard/transport

# Create keycard instance
let t = newTransport()
var card = newKeycard(t)

# Connect to first reader
let readers = card.listReaders()
card.connect(readers[0])
defer: card.close()

# Select the Keycard applet
let result = card.select()
if result.success:
  echo "Card version: ", card.version()
  echo "Initialized: ", card.isInitialized()
  echo "Secure channel: ", card.hasSecureChannel()
```

## Project Structure

```
src/keycard/
├── keycard.nim           # Main Keycard type and high-level API
├── transport.nim         # Low-level APDU communication
├── apdu.nim             # APDU construction utilities
├── constants.nim        # Protocol constants and enums
├── tlv.nim              # BER-TLV parsing
├── util.nim             # Utility functions
├── pcsc_shim.nim        # Mock/real PC/SC abstraction
├── commands/            # Command implementations
│   └── select.nim       # SELECT command
└── types/
    └── application_info.nim  # Application info parsing

tests/
├── transport_test.nim   # Transport layer tests
└── select_test.nim      # SELECT command tests

example/
└── example.nim          # Interactive CLI example
```

## Testing

Run tests with mock PC/SC (no hardware required):

```bash
nimble test
```

Run example with real card:

```bash
nimble example
```

Clean build artifacts:

```bash
nimble clean
```

## Implementation Status

### Core Infrastructure
- ✅ Transport layer with Result types
- ✅ APDU construction with default parameters
- ✅ Mock PC/SC for testing
- ✅ BER-TLV parser
- ✅ Application info structure

### Commands

#### Status Legend
- ✅ Implemented and tested
- 🚧 In progress
- ⏳ Planned
- ❌ Not started

| Command | Status | Description |
|---------|--------|-------------|
| SELECT | ✅ | Select Keycard applet, parse application info |
| INIT | ❌ | Initialize card with PIN, PUK, and pairing secret |
| IDENT | ❌ | Send identity challenge to card |
| OPEN SECURE CHANNEL | ❌ | Establish encrypted communication |
| MUTUALLY AUTHENTICATE | ❌ | Mutual authentication between host and card |
| PAIR | ❌ | Pair with card using ECDH |
| UNPAIR | ❌ | Remove pairing slot |
| GET STATUS | ❌ | Retrieve card status (PIN retries, etc.) |
| VERIFY PIN | ❌ | Verify user PIN |
| CHANGE PIN | ❌ | Change user PIN |
| UNBLOCK PIN | ❌ | Unblock PIN using PUK |
| LOAD KEY | ❌ | Load cryptographic key to card |
| DERIVE KEY | ❌ | Derive key using BIP32 path |
| GENERATE MNEMONIC | ❌ | Generate BIP39 mnemonic on card |
| REMOVE KEY | ❌ | Remove key from card |
| GENERATE KEY | ❌ | Generate new key on card |
| SIGN | ❌ | Sign data with loaded key |
| SET PINLESS PATH | ❌ | Set path for PIN-less signing |
| EXPORT KEY | ❌ | Export public key or key pair |
| STORE DATA | ❌ | Store data in card slots |
| GET DATA | ❌ | Retrieve stored data |
| FACTORY RESET | ❌ | Reset card to factory state |

### Secure Channel
- ❌ AES encryption/decryption
- ❌ MAC generation and verification
- ❌ Session management
- ❌ ECDH key agreement

### Cryptography
- ❌ ECDSA signing
- ❌ BIP32 key derivation
- ❌ BIP39 mnemonic handling

## Design Philosophy

### Idiomatic Nim
- **Result types** instead of exceptions for expected errors
- **Simple data types** with public fields instead of getters/setters
- **Procedural style** with clear, explicit code
- **Compile-time safety** where possible

### Architecture
- **Transport layer**: Handles low-level PC/SC communication
- **Command layer**: Implements protocol commands, interprets status words
- **Keycard layer**: Manages state, provides high-level API

## Contributing

Contributions welcome! Please:
1. Run tests before submitting (`nimble test`)
2. Follow existing code style
3. Add tests for new features
4. Update this README with implementation status

## License

MIT

## References

- [Keycard Protocol](https://keycard.tech/docs/sdk/introduction.html)
- [Status Keycard](https://github.com/status-im/status-keycard)
- [PC/SC Specification](https://en.wikipedia.org/wiki/PC/SC)