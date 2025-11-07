## Constants for Keycard APDU communication

const
  # Keycard Application Identifier
  KeycardAid* = [byte 0xA0, 0x00, 0x00, 0x08, 0x04, 0x00, 0x01, 0x01]
  
  # APDU Class bytes
  ClaIso7816* = 0x00'u8
  ClaProprietary* = 0x80'u8
  
  # APDU Instructions
  InsSelect* = 0xA4'u8
  InsInit* = 0xFE'u8
  InsIdent* = 0x14'u8
  InsOpenSecureChannel* = 0x10'u8
  InsMutuallyAuthenticate* = 0x11'u8
  InsPair* = 0x12'u8
  InsUnpair* = 0x13'u8
  InsVerifyPin* = 0x20'u8
  InsGetStatus* = 0xF2'u8
  InsFactoryReset* = 0xFD'u8
  InsGenerateKey* = 0xD4'u8
  InsChangeSecret* = 0x21'u8
  InsUnblockPin* = 0x22'u8
  InsStoreData* = 0xE2'u8
  InsGetData* = 0xCA'u8
  InsSign* = 0xC0'u8
  InsSetPinlessPath* = 0xC1'u8
  InsExportKey* = 0xC2'u8
  InsLoadKey* = 0xD0'u8
  InsDeriveKey* = 0xD1'u8
  InsGenerateMnemonic* = 0xD2'u8
  InsRemoveKey* = 0xD3'u8
  
  # Status words
  SwSuccess* = 0x9000'u16
  
  # Wrong length / Invalid data (0x6A family)
  SwWrongData* = 0x6A80'u16              # Wrong data / Invalid data format
  SwFunctionNotSupported* = 0x6A81'u16   # Function not supported
  SwNotEnoughMemory* = 0x6A84'u16        # Not enough memory / No space
  SwIncorrectP1P2* = 0x6A86'u16          # Incorrect parameters P1-P2
  SwReferencedDataNotFound* = 0x6A88'u16 # Referenced data not found
  
  # Security related (0x69 family)
  SwSecurityStatusNotSatisfied* = 0x6982'u16  # Security condition not satisfied
  SwConditionsNotSatisfied* = 0x6985'u16      # Conditions of use not satisfied
  
  # Instruction related (0x6D family)
  SwInsNotSupported* = 0x6D00'u16  # Instruction not supported / Already initialized
  
  # Verification (0x63 family)
  SwVerificationFailed* = 0x63C0'u16      # Verification failed (base, counter in lower nibble)
  SwVerificationFailedMask* = 0xFFF0'u16  # Mask to check for verification failed status
  SwRetryCounterMask* = 0x000F'u16        # Mask to extract retry counter

  # BER-TLV Tags for SELECT response
  TagApplicationInfo* = 0xA4'u8
  TagInstanceUid* = 0x8F'u8
  TagPublicKey* = 0x80'u8
  TagAppVersion* = 0x02'u8
  TagKeyUid* = 0x8E'u8
  TagCapabilities* = 0x8D'u8

  # Derivation source constants (can be OR'd with P1)
  # Used by SIGN, EXPORT KEY, and DERIVE KEY commands
  DeriveMaster* = 0x00'u8    # Derive from master key
  DeriveParent* = 0x40'u8    # Derive from parent key
  DeriveCurrent* = 0x80'u8   # Derive from current key

  # Cryptographic sizes
  AesKeySize* = 32           # AES-256 key size in bytes
  AesBlockSize* = 16         # AES block/IV size in bytes
  AesMacSize* = 16           # AES-CBC-MAC output size in bytes
  
  Sha256Size* = 32           # SHA-256 output size in bytes
  Sha512Size* = 64           # SHA-512 output size in bytes
  
  Secp256k1PrivateKeySize* = 32      # secp256k1 private key size
  Secp256k1CoordinateSize* = 32      # secp256k1 point coordinate size (x or y)
  Secp256k1UncompressedSize* = 65    # Uncompressed public key (0x04 + x + y)
  Secp256k1SignatureSize* = 64       # ECDSA signature size (r + s, without recovery id)
  
  Bip39SeedSize* = 64        # BIP39 seed size in bytes
  Bip32ChainCodeSize* = 32   # BIP32 chain code size in bytes
  
  # Credential sizes
  PinLength* = 6             # PIN must be 6 digits
  PukLength* = 12            # PUK must be 12 digits
  PairingSecretLength* = 32  # Pairing Secred 
  
  # Other crypto constants
  PairingPbkdf2Iterations* = 50000   # PBKDF2 iterations for pairing token
  DerIntegerMaxSize* = 33            # Max DER integer encoding (32 + sign byte)

  # APDU limits
  MaxApduDataLength* = 255   # Maximum data length for short APDU format
  
  # TLV Tags
  TagSignatureTemplate* = 0xA0'u8    # Signature template
  TagKeypairTemplate* = 0xA1'u8      # Keypair template  
  TagTlvPublicKey* = 0x80'u8         # Public key in TLV template
  TagTlvPrivateKey* = 0x81'u8        # Private key in TLV template
  TagTlvChainCode* = 0x82'u8         # Chain code in TLV template
  TagDerSequence* = 0x30'u8          # DER SEQUENCE tag
  
  # ISO/IEC 9797-1 Method 2 padding
  IsoPaddingMarker* = 0x80'u8        # Padding marker byte
  
  # BIP32 constants
  Bip32HardenedBit* = 0x8000_0000'u32  # Hardened derivation bit

type
  # Capability flags (bitwise OR)
  Capability* = enum
    CapSecureChannel = 0x01
    CapKeyManagement = 0x02
    CapCredentials = 0x04
    CapNdef = 0x08