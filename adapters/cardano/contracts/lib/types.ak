/// Shared datum and redeemer types for the broker validators.

/// Registry datum — held in a single reference UTXO.
pub type RegistryDatum {
  operator_pkh: ByteArray,
  ecies_pubkey: ByteArray,
  capacity_status: Int,
  region: ByteArray,
  requests_validator_hash: ByteArray,
  beacon_policy_id: ByteArray,
}

/// Request datum — created by client at the broker validator address.
pub type RequestDatum {
  nft_policy_id: ByteArray,
  client_pkh: ByteArray,
  encrypted_payload: ByteArray,
}

/// Response datum — created by broker when consuming a request.
pub type ResponseDatum {
  client_pkh: ByteArray,
  encrypted_response: ByteArray,
}

/// Redeemer actions for the broker validator.
/// Note: there is no CreateRequest — sending to a script address does not
/// invoke the spend validator in Cardano's EUTXO model. Request creation
/// is validated entirely by the beacon minting policy.
pub type BrokerAction {
  ConsumeRequest
  ConsumeResponse
}

/// Redeemer actions for the registry validator.
pub type RegistryAction {
  UpdateRegistry
}

/// Redeemer actions for the beacon minting policy.
pub type BeaconAction {
  MintRequestBeacon
  BurnRequestBeacon
  MintResponseBeacon
  BurnResponseBeacon
}
