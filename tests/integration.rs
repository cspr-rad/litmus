use std::collections::BTreeMap;

use casper_litmus::{
    block::{Block, BlockBody},
    block_header::BlockHeader,
    json_compatibility::{JsonBlock, JsonBlockHeader},
    kernel::LightClientKernel,
};
use casper_types::{
    bytesrepr::{deserialize_from_slice, ToBytes},
    EraId,
};
use once_cell::sync::Lazy;

static BLOCKS_MAP: Lazy<BTreeMap<u64, JsonBlock>> = Lazy::new(|| {
    let mut blocks = BTreeMap::new();
    let cwd = std::env::current_dir().unwrap();
    let this_files_directory = std::path::Path::new(&(file!())).parent().unwrap();
    let blocks_path = cwd.join(this_files_directory).join("assets/blocks");
    for entry in std::fs::read_dir(blocks_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let data = std::fs::read_to_string(path).unwrap();
            let json_block: JsonBlock = serde_json::from_str(&data).unwrap();
            blocks.insert(json_block.header().height(), json_block);
        }
    }
    blocks
});

#[test]
fn parse_block() {
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("assets/blocks/block-0.json")).unwrap();
    assert_eq!(json_block.header().era_id(), EraId::new(0));
}

#[test]
fn first_entry_in_blocks_map_is_correct() {
    let first_block = BLOCKS_MAP.get(&0).unwrap();
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("assets/blocks/block-0.json")).unwrap();
    assert_eq!(first_block, &json_block);
}

#[test]
fn json_block_header_round_trip() {
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("assets/blocks/block-0.json")).unwrap();
    let converted_block_header = BlockHeader::from(json_block.header().clone());
    let reconstituted_json_block_header = JsonBlockHeader::from(converted_block_header.clone());
    assert_eq!(json_block.header(), &reconstituted_json_block_header);
}

#[test]
fn parse_and_validate_hash_of_block() {
    let casper_node_json_block: casper_node::types::JsonBlock =
        serde_json::from_str(include_str!("mainnet/blocks/block-0.json")).unwrap();
    let casper_node_block_header =
        casper_node::types::BlockHeader::from(casper_node_json_block.header.clone());
    assert_eq!(
        casper_node_block_header.block_hash().as_ref(),
        casper_node_json_block.hash.as_ref(),
        "Casper node block hash mismatch"
    );
    let block_header_bytes = casper_node_block_header.to_bytes().unwrap();
    let deserialized_block_header: BlockHeader =
        deserialize_from_slice(&block_header_bytes).unwrap();
    assert_eq!(
        deserialized_block_header.block_hash().as_ref(),
        casper_node_json_block.hash.as_ref(),
        "JSON block hash mismatch"
    );
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("mainnet/blocks/block-0.json")).unwrap();
    let converted_block_header = BlockHeader::from(json_block.header().clone());
    assert_eq!(
        deserialized_block_header, converted_block_header,
        "Block header mismatch"
    );
}

#[test]
fn parse_and_validate_hash_of_block_body() {
    let casper_node_json_block: casper_node::types::JsonBlock =
        serde_json::from_str(include_str!("mainnet/blocks/block-0.json")).unwrap();
    let casper_node_block_body =
        casper_node::types::BlockBody::from(casper_node_json_block.body.clone());
    assert_eq!(
        casper_node_block_body.hash().as_ref(),
        casper_node_json_block.header.body_hash.as_ref(),
        "Casper node block body hash mismatch"
    );
    let block_body_bytes = casper_node_block_body.to_bytes().unwrap();
    let deserialized_block_body: BlockBody = deserialize_from_slice(&block_body_bytes).unwrap();
    assert_eq!(
        deserialized_block_body.hash().as_ref(),
        casper_node_json_block.header.body_hash.as_ref(),
        "JSON block body hash mismatch"
    );
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("mainnet/blocks/block-0.json")).unwrap();
    let converted_block_body = BlockBody::from(json_block.body().clone());
    assert_eq!(
        deserialized_block_body, converted_block_body,
        "Block body mismatch"
    );
}

#[test]
fn update_kernel_one() {
    let mut kernel = LightClientKernel::new(BLOCKS_MAP.get(&0).unwrap().hash().clone());
    let json_block: JsonBlock =
        serde_json::from_str(include_str!("assets/blocks/block-0.json")).unwrap();
    let block = Block::try_from(json_block.clone()).unwrap();
    let result = kernel.update(block.block_header_with_signatures());
    assert!(result.is_ok());
}

#[test]
fn update_kernel_history() {
    let mut kernel = LightClientKernel::new(BLOCKS_MAP.get(&0).unwrap().hash().clone());
    for height in 0..BLOCKS_MAP.len() {
        let json_block = BLOCKS_MAP.get(&(height as u64)).unwrap();
        let block = Block::try_from(json_block.clone()).unwrap();
        kernel.update(block.block_header_with_signatures()).unwrap();
        assert_eq!(kernel.latest_block_hash(), json_block.hash());
    }
}
