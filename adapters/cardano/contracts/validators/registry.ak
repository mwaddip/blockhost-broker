use aiken/collection/list
use cardano/transaction.{InlineDatum, Output, OutputReference, Transaction,
  find_input}
use types.{RegistryAction, RegistryDatum, UpdateRegistry}

/// Registry validator: holds a single reference UTXO with broker info.
/// Only the operator can update it (must re-produce at same address with valid datum).
/// Clients read it as a reference input (no contention).
validator registry {
  spend(
    datum: Option<RegistryDatum>,
    redeemer: RegistryAction,
    own_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(d) = datum
    when redeemer is {
      UpdateRegistry -> {
        // Must be signed by the operator
        let signed = list.has(tx.extra_signatories, d.operator_pkh)

        // Must produce exactly one output back to the same address
        expect Some(own_input) = find_input(tx.inputs, own_ref)
        let own_address = own_input.output.address

        let continuing_outputs =
          list.filter(tx.outputs, fn(o: Output) { o.address == own_address })

        let has_one_continuing = list.length(continuing_outputs) == 1

        // The continuing output must have an inline datum
        expect [continuing_output] = continuing_outputs
        expect InlineDatum(_) = continuing_output.datum

        signed && has_one_continuing
      }
    }
  }

  else(_) {
    fail
  }
}
