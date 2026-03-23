use aiken/collection/list
use cardano/address.{Script}
use cardano/assets
use cardano/transaction.{InlineDatum, Output, Transaction}
use types.{
  BeaconAction, BurnRequestBeacon, BurnResponseBeacon, MintRequestBeacon,
  MintResponseBeacon, RequestDatum,
}

/// Beacon minting policy, parameterized with the broker validator hash
/// and operator pubkey hash.
///
/// Two token names:
///   "request"  — minted when creating a request UTXO, burned by broker
///   "response" — minted when broker produces a response UTXO, burned by client
///
/// All mint conditions verify that outputs go to the address derived from
/// the parameterized broker_validator_hash.
validator beacon(broker_validator_hash: ByteArray, operator_pkh: ByteArray) {
  mint(redeemer: BeaconAction, policy_id: ByteArray, tx: Transaction) {
    let validator_credential = Script(broker_validator_hash)

    let outputs_at_validator =
      list.filter(
        tx.outputs,
        fn(o: Output) {
          o.address.payment_credential == validator_credential
        },
      )

    when redeemer is {
      MintRequestBeacon -> {
        // Must mint exactly 1 request beacon
        let mint_count =
          assets.quantity_of(tx.mint, policy_id, "request")
        let only_one = mint_count == 1

        // Must produce at least one UTXO at the validator
        let has_output = list.length(outputs_at_validator) >= 1

        // The output must carry the beacon token
        let output_has_beacon =
          list.any(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, "request") == 1
            },
          )

        // The output must have an inline datum with a valid RequestDatum.
        // The client_pkh in the datum must be a signer of this transaction,
        // proving the requester controls that wallet.
        expect Some(beacon_output) =
          list.find(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, "request") == 1
            },
          )
        expect InlineDatum(raw) = beacon_output.datum
        expect req: RequestDatum = raw

        let client_signed =
          list.has(tx.extra_signatories, req.client_pkh)

        only_one && has_output && output_has_beacon && client_signed
      }

      BurnRequestBeacon -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // Must burn exactly 1 request beacon
        let burn_count =
          assets.quantity_of(tx.mint, policy_id, "request")
        let burns_one = burn_count == -1

        signed && burns_one
      }

      MintResponseBeacon -> {
        // Must be signed by broker operator
        let signed = list.has(tx.extra_signatories, operator_pkh)

        // Must mint exactly 1 response beacon
        let mint_count =
          assets.quantity_of(tx.mint, policy_id, "response")
        let only_one = mint_count == 1

        // Must produce a UTXO at the validator with the beacon
        let output_has_beacon =
          list.any(
            outputs_at_validator,
            fn(o: Output) {
              assets.quantity_of(o.value, policy_id, "response") == 1
            },
          )

        signed && only_one && output_has_beacon
      }

      BurnResponseBeacon -> {
        // Must burn exactly 1 response beacon
        let burn_count =
          assets.quantity_of(tx.mint, policy_id, "response")
        let burns_one = burn_count == -1

        // Must consume a response UTXO from the broker validator
        // (the spend validator's ConsumeResponse enforces client_pkh signature)
        let consumes_validator_utxo =
          list.any(
            tx.inputs,
            fn(i) {
              i.output.address.payment_credential == validator_credential && assets.quantity_of(
                i.output.value,
                policy_id,
                "response",
              ) == 1
            },
          )

        burns_one && consumes_validator_utxo
      }
    }
  }

  else(_) {
    fail
  }
}
