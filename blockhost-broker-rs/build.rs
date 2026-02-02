use ethers::contract::Abigen;
use std::path::Path;

fn main() {
    // Generate contract bindings from ABIs
    let abi_dir = Path::new("contracts/abi");

    if abi_dir.exists() {
        // BrokerRequests contract
        let requests_abi = abi_dir.join("BrokerRequests.json");
        if requests_abi.exists() {
            Abigen::new("BrokerRequests", requests_abi.to_str().unwrap())
                .unwrap()
                .generate()
                .unwrap()
                .write_to_file("src/eth/broker_requests.rs")
                .unwrap();
        }

        // BrokerRegistry contract
        let registry_abi = abi_dir.join("BrokerRegistry.json");
        if registry_abi.exists() {
            Abigen::new("BrokerRegistry", registry_abi.to_str().unwrap())
                .unwrap()
                .generate()
                .unwrap()
                .write_to_file("src/eth/broker_registry.rs")
                .unwrap();
        }
    }

    println!("cargo:rerun-if-changed=contracts/abi/");
}
