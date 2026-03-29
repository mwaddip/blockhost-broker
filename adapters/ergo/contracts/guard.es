{
  // Broker request/response guard script.
  //
  // Parameterized with operator's compressed public key (constant 0).
  // Two spending paths:
  //   1. Respond: operator signs, beacon carried to successor box
  //   2. Client:  client signs (cancel request or cleanup response)
  //
  // Register layout:
  //   R4: Coll[Byte] — client compressed public key (33 bytes)
  //   R5: Coll[Byte] — encrypted payload (request) or response (response)
  //   tokens(0): beacon token (amount = 1)

  val operatorPk = decodePoint(fromBase64("$$OPERATOR_PK_BASE64$$"))
  val clientPkBytes = SELF.R4[Coll[Byte]].get
  val clientPk = decodePoint(clientPkBytes)
  val beaconId = SELF.tokens(0)._1

  // Path 1: Operator responds — creates successor with same beacon + script + client PK
  val successor = OUTPUTS(0)
  val beaconPreserved = successor.tokens.size > 0 &&
                        successor.tokens(0)._1 == beaconId &&
                        successor.tokens(0)._2 == 1L
  val sameScript = successor.propositionBytes == SELF.propositionBytes
  val clientPreserved = successor.R4[Coll[Byte]].get == clientPkBytes

  val respondPath = sigmaProp(beaconPreserved && sameScript && clientPreserved) && proveDlog(operatorPk)

  // Path 2: Client spends (cancel request or cleanup response)
  val clientPath = proveDlog(clientPk)

  respondPath || clientPath
}
