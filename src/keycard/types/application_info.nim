## Application Info structure from SELECT response

import pcsc/util as putil
import ../tlv
import ../constants

type
  ApplicationInfo* = object
    instanceUid*: seq[byte]
    publicKey*: seq[byte]
    appVersion*: tuple[major, minor: byte]
    freeSlots*: byte
    keyUid*: seq[byte]
    capabilities*: byte

proc isInitialized*(info: ApplicationInfo): bool =
  info.instanceUid.len > 0

proc hasSecureChannel*(info: ApplicationInfo): bool =
  (info.capabilities and byte(CapSecureChannel)) != 0

proc hasKeyManagement*(info: ApplicationInfo): bool =
  (info.capabilities and byte(CapKeyManagement)) != 0

proc hasCredentials*(info: ApplicationInfo): bool =
  (info.capabilities and byte(CapCredentials)) != 0

proc hasNdef*(info: ApplicationInfo): bool =
  (info.capabilities and byte(CapNdef)) != 0

proc parseApplicationInfo*(data: openArray[byte]): ApplicationInfo =
  ## Parse SELECT response data into ApplicationInfo
  ## 
  ## Handles both:
  ## - Pre-initialized state: just public key (tag 0x80)
  ## - Initialized state: full Application Info Template (tag 0xA4)
  
  result = ApplicationInfo()
  
  if data.len > 0 and data[0] == TagPublicKey:
    let tags = parseTlv(data)
    result.publicKey = tags.findTag(TagPublicKey)
    result.freeSlots = 0xFF
    return
  
  if data.len > 0 and data[0] == TagApplicationInfo:
    let outerTags = parseTlv(data)
    let templateData = outerTags.findTag(TagApplicationInfo)
    
    if templateData.len > 0:
      let tags = parseTlv(templateData)
      
      result.instanceUid = tags.findTag(TagInstanceUid)
      result.publicKey = tags.findTag(TagPublicKey)
      result.keyUid = tags.findTag(TagKeyUid)
      
      # Parse version (2 bytes)
      let versionBytes = tags.findTag(TagAppVersion)
      if versionBytes.len >= 2:
        result.appVersion = (versionBytes[0], versionBytes[1])
      
      # Parse free slots
      # Note: Tag 0x02 appears twice in the template:
      #   - First occurrence: 2-byte application version (major, minor)
      #   - Second occurrence: 1-byte free pairing slots
      # We differentiate by checking the value length
      for tag in tags:
        if tag.tag == TagAppVersion and tag.value.len == 1:
          result.freeSlots = tag.value[0]
          break
      
      # Parse capabilities
      let capBytes = tags.findTag(TagCapabilities)
      if capBytes.len > 0:
        result.capabilities = capBytes[0]

proc `$`*(info: ApplicationInfo): string =
  ## Pretty print ApplicationInfo
  result = "ApplicationInfo:\n"
  
  if info.instanceUid.len > 0:
    result.add "  Instance UID: " & info.instanceUid.prettyHex() & "\n"
  
  if info.publicKey.len > 0:
    result.add "  Public Key: " & info.publicKey[0..10].prettyHex() & "...\n"
  
  result.add "  Version: " & $info.appVersion.major & "." & $info.appVersion.minor & "\n"
  result.add "  Free Slots: " & $info.freeSlots & "\n"
  
  if info.keyUid.len > 0:
    result.add "  Key UID: " & info.keyUid.prettyHex() & "\n"
  
  result.add "  Capabilities:\n"
  if info.hasSecureChannel(): result.add "    - Secure Channel\n"
  if info.hasKeyManagement(): result.add "    - Key Management\n"
  if info.hasCredentials(): result.add "    - Credentials\n"
  if info.hasNdef(): result.add "    - NDEF\n"
  
  result.add "  Initialized: " & $info.isInitialized()