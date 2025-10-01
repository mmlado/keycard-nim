# Compile with -d:mockPcsc to use the mock; otherwise re-export the real pcsc.

when defined(mockPcsc):
  type
    PcscContext* = ref object
      readers*: seq[string]

    PcscCard* = ref object
      scripted*: seq[seq[byte]]
      txLog*: seq[seq[byte]]

  proc establishContext*(): PcscContext =
    PcscContext(readers: @["Mock Reader A", "Mock Reader B"])

  proc listReaders*(ctx: PcscContext): seq[string] =
    ctx.readers

  proc connect*(ctx: PcscContext; reader: string): PcscCard =
    discard reader # unused in mock
    PcscCard(scripted: @[], txLog: @[])

  proc transmit*(c: PcscCard; apdu: seq[byte]): seq[byte] =
    c.txLog.add apdu
    if c.scripted.len > 0:
      result = c.scripted[0]
      c.scripted.delete(0)
    else:
      result = @[byte(0x90), byte(0x00)]

  proc disconnect*(c: PcscCard) = discard

  proc mockSetScriptedResponses*(c: PcscCard; rs: seq[seq[byte]]) =
    c.scripted = rs

  proc mockTxLog*(c: PcscCard): seq[seq[byte]] = c.txLog

else:
  import pcsc as real
  export real
  import pcsc/core

  proc disconnect*(c: real.PcscCard) =
    var card = c
    real.disconnect(card, SCARD_LEAVE_CARD)