use casper_litmus::{
    block_header::BlockHeaderV1,
    json_compatibility::{JsonBlock, JsonBlockHeader},
    merkle_proof::{process_query_proofs, TrieMerkleProof},
};

#[test]
fn json_block_header_round_trip() {
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("assets/blocks/block-0.json")).unwrap();
    let converted_block_header = BlockHeaderV1::from(json_block.header().clone());
    let reconstituted_json_block_header = JsonBlockHeader::from(converted_block_header.clone());
    assert_eq!(json_block.header(), &reconstituted_json_block_header);
}

#[test]
fn query_proofs() {
    let proofs_hex = include_str!("assets/query_merkle_proofs.txt");
    let proofs_bytes = hex::decode(proofs_hex).expect("should decode with hex");
    let proofs: Vec<TrieMerkleProof> = casper_types::bytesrepr::deserialize(proofs_bytes)
        .expect("should deserialize with bytesrepr");
    let query_info = process_query_proofs(&proofs, &[]).unwrap();
    assert_eq!(
        "9253bf8484bae2b6e4d5302c792c6a79f729b2cc2a9d87beb262d3266a424efa",
        query_info.state_root().to_hex(),
        "hex of state root not as expected"
    );
    if let casper_types::StoredValue::Account(account) = query_info.stored_value() {
        assert_eq!(
            "account-hash-c39d7a6202e5558ffbf327985c55a95f606db48115599a216987b73daf409076",
            serde_json::to_value(account.account_hash())
                .expect("should convert to serde_json::Value")
                .as_str()
                .expect("should be a string"),
            "account hash not as expected"
        );
    } else {
        panic!(
            "StoredValue variant not as expected (should be Account): {:?}",
            query_info.stored_value()
        );
    }
    if let casper_types::Key::Account(account_hash) = query_info.key() {
        assert_eq!(
            "account-hash-c39d7a6202e5558ffbf327985c55a95f606db48115599a216987b73daf409076",
            serde_json::to_value(account_hash)
                .expect("should convert to serde_json::Value")
                .as_str()
                .expect("should be a string")
        );
    } else {
        panic!(
            "Key variant not as expected (should be Account): {:?}",
            query_info.key()
        );
    }
}
