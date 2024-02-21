use alloc::{collections::BTreeMap, vec::Vec};

use casper_types::{
    bytesrepr::{FromBytes, ToBytes},
    verify, EraId, Error as SignatureVerificationError, PublicKey, Signature,
};
use proptest::prelude::*;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Serialize};

use super::{
    block_header::{BlockHash, BlockHeader},
    crypto::{arb_pubkey, arb_signature},
    hash::Digest,
};

#[derive(Clone, Debug, PartialOrd, Ord, Serialize, Deserialize, Eq, PartialEq)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1324-L1332
pub struct BlockSignatures {
    /// The block hash for a given block.
    block_hash: BlockHash,
    /// The era id for the given set of finality signatures.
    era_id: EraId,
    /// The signatures associated with the block hash.
    proofs: BTreeMap<PublicKey, Signature>,
}

impl BlockSignatures {
    pub fn new(
        block_hash: BlockHash,
        era_id: EraId,
        proofs: BTreeMap<PublicKey, Signature>,
    ) -> Self {
        BlockSignatures {
            block_hash,
            era_id,
            proofs,
        }
    }

    pub fn block_hash(&self) -> &BlockHash {
        &self.block_hash
    }

    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    pub fn proofs(&self) -> &BTreeMap<PublicKey, Signature> {
        &self.proofs
    }

    pub fn verify(&self) -> Result<(), SignatureVerificationError> {
        for (public_key, signature) in &self.proofs {
            verify(&self.block_hash, signature, public_key)?;
        }
        Ok(())
    }
}

impl Arbitrary for BlockSignatures {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<BlockHash>(),
            any::<u64>(), // EraId
            prop::collection::btree_map(arb_pubkey(), arb_signature(), 0..5),
        )
            .prop_map(|(block_hash, era_id, proofs)| {
                let era_id = EraId::from(era_id);
                BlockSignatures {
                    block_hash,
                    era_id,
                    proofs,
                }
            })
            .boxed()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1184-L1188
pub struct BlockHeaderWithSignatures {
    block_header: BlockHeader,
    block_signatures: BlockSignatures,
}

impl BlockHeaderWithSignatures {
    pub fn new(block_header: BlockHeader, block_signatures: BlockSignatures) -> Self {
        BlockHeaderWithSignatures {
            block_header,
            block_signatures,
        }
    }

    pub fn block_header(&self) -> &BlockHeader {
        &self.block_header
    }

    pub fn block_signatures(&self) -> &BlockSignatures {
        &self.block_signatures
    }
}

#[derive(
    Arbitrary, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize, Debug,
)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L32
pub struct DeployHash(Digest);

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L89-L101
impl ToBytes for DeployHash {
    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), casper_types::bytesrepr::Error> {
        self.0.write_bytes(writer)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/deploy/deploy_hash.rs#L103-L107
impl FromBytes for DeployHash {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        Digest::from_bytes(bytes).map(|(inner, remainder)| (DeployHash(inner), remainder))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1204C14-L1204C15
pub struct BlockBody {
    proposer: PublicKey,
    deploy_hashes: Vec<DeployHash>,
    transfer_hashes: Vec<DeployHash>,
}

impl BlockBody {
    pub fn new(
        proposer: PublicKey,
        deploy_hashes: Vec<DeployHash>,
        transfer_hashes: Vec<DeployHash>,
    ) -> Self {
        BlockBody {
            proposer,
            deploy_hashes,
            transfer_hashes,
        }
    }

    pub fn proposer(&self) -> &PublicKey {
        &self.proposer
    }

    pub fn deploy_hashes(&self) -> &[DeployHash] {
        &self.deploy_hashes
    }

    pub fn transfer_hashes(&self) -> &[DeployHash] {
        &self.transfer_hashes
    }
}

impl Arbitrary for BlockBody {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            arb_pubkey(),
            prop::collection::vec(any::<DeployHash>(), 0..5),
            prop::collection::vec(any::<DeployHash>(), 0..5),
        )
            .prop_map(|(proposer, deploy_hashes, transfer_hashes)| BlockBody {
                proposer,
                deploy_hashes,
                transfer_hashes,
            })
            .boxed()
    }
}

// See: https://github.com/casper-network/casper-node/blob/edc4b45ea05526ba6dd7971da09e27754a37a230/node/src/types/block.rs#L1292-L1306
impl ToBytes for BlockBody {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut buffer = casper_types::bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.proposer.to_bytes()?);
        buffer.extend(self.deploy_hashes.to_bytes()?);
        buffer.extend(self.transfer_hashes.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.proposer.serialized_length()
            + self.deploy_hashes.serialized_length()
            + self.transfer_hashes.serialized_length()
    }
}

impl FromBytes for BlockBody {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (proposer, bytes) = PublicKey::from_bytes(bytes)?;
        let (deploy_hashes, bytes) = Vec::<DeployHash>::from_bytes(bytes)?;
        let (transfer_hashes, bytes) = Vec::<DeployHash>::from_bytes(bytes)?;
        let body = BlockBody {
            proposer,
            deploy_hashes,
            transfer_hashes,
        };
        Ok((body, bytes))
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use alloc::collections::BTreeMap;

    use casper_types::bytesrepr::ToBytes;
    use casper_types::PublicKey;
    use test_strategy::proptest;

    use crate::{block_header::BlockHash, crypto::sign, hash::DIGEST_LENGTH};

    use super::{BlockSignatures, DeployHash};

    #[proptest]
    fn serde_json_block_signatures_round_trip(block_signatures: BlockSignatures) {
        let serialized_block_signatures = serde_json::to_string(&block_signatures).unwrap();
        let casper_types_block_signatures: casper_node::types::BlockSignatures =
            serde_json::from_str(&serialized_block_signatures).unwrap();
        let serialized_casper_types_block_signatures =
            serde_json::to_string(&casper_types_block_signatures).unwrap();
        assert_eq!(
            serialized_block_signatures,
            serialized_casper_types_block_signatures
        );
        let deserialized_block_signatures: BlockSignatures =
            serde_json::from_str(&serialized_casper_types_block_signatures).unwrap();
        assert_eq!(block_signatures, deserialized_block_signatures);
    }

    #[proptest]
    fn bincode_block_signatures_round_trip(block_signatures: BlockSignatures) {
        let serialized_block_signatures = bincode::serialize(&block_signatures).unwrap();
        let casper_types_block_signatures: casper_node::types::BlockSignatures =
            bincode::deserialize(&serialized_block_signatures).unwrap();
        let serialized_casper_types_block_signatures =
            bincode::serialize(&casper_types_block_signatures).unwrap();
        assert_eq!(
            serialized_block_signatures,
            serialized_casper_types_block_signatures
        );
        let deserialized_block_signatures: BlockSignatures =
            bincode::deserialize(&serialized_casper_types_block_signatures).unwrap();
        assert_eq!(block_signatures, deserialized_block_signatures);
    }

    #[test]
    fn should_verify() {
        let secret_key = casper_types::SecretKey::ed25519_from_bytes([42; 32]).unwrap();
        let block_hash = BlockHash::from([42; DIGEST_LENGTH]);
        let signature = sign(&secret_key, &block_hash);
        let mut proofs = BTreeMap::new();
        proofs.insert(PublicKey::from(&secret_key), signature);
        let block_signatures = BlockSignatures::new(block_hash, 0.into(), proofs);
        assert!(block_signatures.verify().is_ok());
    }

    #[test]
    fn should_not_verify() {
        let secret_key0 = casper_types::SecretKey::ed25519_from_bytes([42; 32]).unwrap();
        let secret_key1 = casper_types::SecretKey::ed25519_from_bytes([43; 32]).unwrap();
        let block_hash = BlockHash::from([42; DIGEST_LENGTH]);
        let bogus_signature = sign(&secret_key1, &block_hash);
        let mut proofs = BTreeMap::new();
        proofs.insert(PublicKey::from(&secret_key0), bogus_signature);
        let block_signatures = BlockSignatures::new(block_hash, 0.into(), proofs);
        assert!(block_signatures.verify().is_err());
    }

    #[proptest]
    fn serde_json_deploy_hash_round_trip(deploy_hash: DeployHash) {
        let serialized_deploy_hash = serde_json::to_string(&deploy_hash).unwrap();
        let casper_types_deploy_hash: casper_types::DeployHash =
            serde_json::from_str(&serialized_deploy_hash).unwrap();
        let serialized_casper_types_deploy_hash =
            serde_json::to_string(&casper_types_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_types_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            serde_json::from_str(&serialized_casper_types_deploy_hash).unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn bincode_deploy_hash_round_trip(deploy_hash: DeployHash) {
        let serialized_deploy_hash = bincode::serialize(&deploy_hash).unwrap();
        let casper_node_deploy_hash: casper_node::types::DeployHash =
            bincode::deserialize(&serialized_deploy_hash).unwrap();
        let serialized_casper_node_deploy_hash =
            bincode::serialize(&casper_node_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_node_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            bincode::deserialize(&serialized_casper_node_deploy_hash).unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }

    #[proptest]
    fn bytesrepr_deploy_hash_round_trip(deploy_hash: DeployHash) {
        let serialized_deploy_hash = deploy_hash.to_bytes().unwrap();
        let casper_types_deploy_hash: casper_types::DeployHash =
            casper_types::bytesrepr::deserialize(serialized_deploy_hash.clone()).unwrap();
        let serialized_casper_types_deploy_hash =
            casper_types::bytesrepr::serialize(&casper_types_deploy_hash).unwrap();
        assert_eq!(serialized_deploy_hash, serialized_casper_types_deploy_hash);
        let deserialized_deploy_hash: DeployHash =
            casper_types::bytesrepr::deserialize(serialized_casper_types_deploy_hash.clone())
                .unwrap();
        assert_eq!(deploy_hash, deserialized_deploy_hash);
    }
}
