# keycard-nim

A Nim SDK to interact with the [Status Keycard](https://keycard.tech) - a hardware wallet implementation on JavaCard.

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

| Command | Status | Description |
|---------|--------|-------------|
| SELECT | ✅ | Select Keycard applet, parse application info |
| INIT | ✅ | Initialize card with PIN, PUK, and pairing secret |
| IDENT | ✅ | Send identity challenge to card |
| OPEN SECURE CHANNEL | ✅ | Establish encrypted communication |
| MUTUALLY AUTHENTICATE | ✅ | Mutual authentication between host and card |
| PAIR | ✅ | Pair with card using ECDH |
| UNPAIR | ✅ | Remove pairing slot |
| GET STATUS | ✅ | Retrieve card status (PIN retries, etc.) |
| VERIFY PIN | ✅ | Verify user PIN |
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
| STORE DATA | ✅ | Store data in card slots |
| GET DATA | ✅ | Retrieve stored data |
| FACTORY RESET | ✅ | Reset card to factory state |

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