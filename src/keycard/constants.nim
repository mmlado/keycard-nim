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
  
  # BER-TLV Tags for SELECT response
  TagApplicationInfo* = 0xA4'u8
  TagInstanceUid* = 0x8F'u8
  TagPublicKey* = 0x80'u8
  TagAppVersion* = 0x02'u8
  TagKeyUid* = 0x8E'u8
  TagCapabilities* = 0x8D'u8

type
  # Capability flags (bitwise OR)
  Capability* = enum
    CapSecureChannel = 0x01
    CapKeyManagement = 0x02
    CapCredentials = 0x04
    CapNdef = 0x08