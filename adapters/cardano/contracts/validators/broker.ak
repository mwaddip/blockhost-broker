use aiken/collection/list
use cardano/assets
use cardano/transaction.{Output, OutputReference, Transaction, find_input}
use types.{BrokerAction, ConsumeRequest, ConsumeResponse, ResponseDatum}

/// Broker validator: handles request/response UTXO lifecycle.
///
/// Sending to this address (creating request UTXOs) does not invoke this
/// validator — that's handled by the beacon minting policy which validates
/// datum structure, NFT presence, and output destination.
///
/// This validator only fires when consuming UTXOs at this address:
/// - ConsumeRequest: broker operator consumes request, produces response
/// - ConsumeResponse: client cleans up response UTXO
validator broker(operator_pkh: ByteArray, beacon_policy_id: ByteArray) {
  spend(
    datum: Option<Data>,
    redeemer: BrokerAction,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    when redeemer is {
      ConsumeRequest -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // The consumed UTXO must carry a request beacon (prevents using
        // this redeemer to consume response UTXOs and bypass ConsumeResponse)
        expect Some(own_input) = find_input(tx.inputs, own_ref)
        let has_request_beacon =
          assets.quantity_of(own_input.output.value, beacon_policy_id, "request") == 1

        // Must produce at least one output back to this validator address
        let own_address = own_input.output.address
        let response_outputs =
          list.filter(tx.outputs, fn(o: Output) { o.address == own_address })
        let has_response = list.length(response_outputs) >= 1

        signed && has_request_beacon && has_response
      }

      ConsumeResponse -> {
        // Must be signed by the client_pkh from the response datum
        expect Some(raw_datum) = datum
        expect response: ResponseDatum = raw_datum
        list.has(tx.extra_signatories, response.client_pkh)
      }
    }
  }

  else(_) {
    fail
  }
}
