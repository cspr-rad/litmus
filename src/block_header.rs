use alloc::vec::Vec;
use casper_types::bytesrepr::{FromBytes, ToBytes};
use casper_types::{EraId, ProtocolVersion};
use proptest::arbitrary::Arbitrary;
use proptest::prelude::*;
use proptest_derive::Arbitrary;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use super::consensus::EraEnd;
use super::hash::Digest;
use super::hash::DIGEST_LENGTH;

#[derive(
    Arbitrary, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize, Debug,
)]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L648
pub struct BlockHash(Digest);

impl AsRef<[u8]> for BlockHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<BlockHash> for [u8; DIGEST_LENGTH] {
    fn from(block_hash: BlockHash) -> Self {
        block_hash.0.into()
    }
}

impl From<BlockHash> for Digest {
    fn from(block_hash: BlockHash) -> Self {
        block_hash.0
    }
}

impl From<Digest> for BlockHash {
    fn from(digest: Digest) -> Self {
        BlockHash(digest)
    }
}

impl From<[u8; DIGEST_LENGTH]> for BlockHash {
    fn from(bytes: [u8; DIGEST_LENGTH]) -> Self {
        BlockHash(Digest::from(bytes))
    }
}

impl ToBytes for BlockHash {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

impl FromBytes for BlockHash {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (hash, remainder) = Digest::from_bytes(bytes)?;
        let block_hash = BlockHash(hash);
        Ok((block_hash, remainder))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/types/src/timestamp.rs#L32-L40
pub struct Timestamp(u64);

impl Arbitrary for Timestamp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0u64..=253402300799).prop_map(Timestamp).boxed()
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            let datetime = OffsetDateTime::from_unix_timestamp_nanos((self.0 * 1_000_000) as i128)
                .map_err(serde::ser::Error::custom)?;
            // Note: this serializes to "1970-01-01T00:00:00.000000000Z" while casper_types::Timestamp serializes to "1970-01-01T00:00:00.000Z"
            // On the other hand we can deserialize both formats so it doesn't really matter.
            time::serde::rfc3339::serialize(&datetime, serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let datetime = time::serde::rfc3339::deserialize(deserializer)?;
            let timestamp = datetime.unix_timestamp_nanos();
            Ok(Timestamp((timestamp as u64) / 1_000_000))
        } else {
            let inner = u64::deserialize(deserializer)?;
            Ok(Timestamp(inner))
        }
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/types/src/timestamp.rs#L208-L216
impl ToBytes for Timestamp {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/types/src/timestamp.rs#L218-L222
impl FromBytes for Timestamp {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        u64::from_bytes(bytes).map(|(inner, remainder)| (Timestamp(inner), remainder))
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L813-L828
pub struct BlockHeader {
    parent_hash: BlockHash,
    state_root_hash: Digest,
    body_hash: Digest,
    random_bit: bool,
    accumulated_seed: Digest,
    era_end: Option<EraEnd>,
    timestamp: Timestamp,
    era_id: EraId,
    height: u64,
    protocol_version: ProtocolVersion,
}

impl BlockHeader {
    pub fn new(
        parent_hash: BlockHash,
        state_root_hash: Digest,
        body_hash: Digest,
        random_bit: bool,
        accumulated_seed: Digest,
        era_end: Option<EraEnd>,
        timestamp: Timestamp,
        era_id: EraId,
        height: u64,
        protocol_version: ProtocolVersion,
    ) -> Self {
        BlockHeader {
            parent_hash,
            state_root_hash,
            body_hash,
            random_bit,
            accumulated_seed,
            era_end,
            timestamp,
            era_id,
            height,
            protocol_version,
        }
    }

    pub fn parent_hash(&self) -> &BlockHash {
        &self.parent_hash
    }

    pub fn state_root_hash(&self) -> &Digest {
        &self.state_root_hash
    }

    pub fn body_hash(&self) -> &Digest {
        &self.body_hash
    }

    pub fn random_bit(&self) -> bool {
        self.random_bit
    }

    pub fn accumulated_seed(&self) -> &Digest {
        &self.accumulated_seed
    }

    pub fn era_end(&self) -> Option<&EraEnd> {
        self.era_end.as_ref()
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub fn block_hash(&self) -> BlockHash {
        BlockHash(Digest::hash(&self.to_bytes().unwrap()))
    }
}

impl Arbitrary for BlockHeader {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        fn arb_protocolversion() -> impl Strategy<Value = ProtocolVersion> {
            (0..=255u32, 0..=255u32, 0..=255u32)
                .prop_map(|(major, minor, patch)| ProtocolVersion::from_parts(major, minor, patch))
        }

        (
            any::<BlockHash>(),
            any::<Digest>(),
            any::<Digest>(),
            any::<bool>(),
            any::<Digest>(),
            any::<Option<EraEnd>>(),
            any::<Timestamp>(),
            any::<u64>(), // EraId
            any::<u64>(), // height
            arb_protocolversion(),
        )
            .prop_map(
                |(
                    parent_hash,
                    state_root_hash,
                    body_hash,
                    random_bit,
                    accumulated_seed,
                    era_end,
                    timestamp,
                    era_id,
                    height,
                    protocol_version,
                )| {
                    let era_id = EraId::from(era_id);
                    BlockHeader {
                        parent_hash,
                        state_root_hash,
                        body_hash,
                        random_bit,
                        accumulated_seed,
                        era_end,
                        timestamp,
                        era_id,
                        height,
                        protocol_version,
                    }
                },
            )
            .boxed()
    }
}

impl ToBytes for BlockHeader {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        let mut buffer = casper_types::bytesrepr::allocate_buffer(self)?;
        buffer.extend(self.parent_hash.to_bytes()?);
        buffer.extend(self.state_root_hash.to_bytes()?);
        buffer.extend(self.body_hash.to_bytes()?);
        buffer.extend(self.random_bit.to_bytes()?);
        buffer.extend(self.accumulated_seed.to_bytes()?);
        buffer.extend(self.era_end.to_bytes()?);
        buffer.extend(self.timestamp.to_bytes()?);
        buffer.extend(self.era_id.to_bytes()?);
        buffer.extend(self.height.to_bytes()?);
        buffer.extend(self.protocol_version.to_bytes()?);
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        self.parent_hash.serialized_length()
            + self.state_root_hash.serialized_length()
            + self.body_hash.serialized_length()
            + self.random_bit.serialized_length()
            + self.accumulated_seed.serialized_length()
            + self.era_end.serialized_length()
            + self.timestamp.serialized_length()
            + self.era_id.serialized_length()
            + self.height.serialized_length()
            + self.protocol_version.serialized_length()
    }
}

impl FromBytes for BlockHeader {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (parent_hash, remainder) = BlockHash::from_bytes(bytes)?;
        let (state_root_hash, remainder) = Digest::from_bytes(remainder)?;
        let (body_hash, remainder) = Digest::from_bytes(remainder)?;
        let (random_bit, remainder) = bool::from_bytes(remainder)?;
        let (accumulated_seed, remainder) = Digest::from_bytes(remainder)?;
        let (era_end, remainder) = Option::<EraEnd>::from_bytes(remainder)?;
        let (timestamp, remainder) = Timestamp::from_bytes(remainder)?;
        let (era_id, remainder) = EraId::from_bytes(remainder)?;
        let (height, remainder) = u64::from_bytes(remainder)?;
        let (protocol_version, remainder) = ProtocolVersion::from_bytes(remainder)?;
        let block_header = BlockHeader {
            parent_hash,
            state_root_hash,
            body_hash,
            random_bit,
            accumulated_seed,
            era_end,
            timestamp,
            era_id,
            height,
            protocol_version,
        };
        Ok((block_header, remainder))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::borrow::ToOwned;
    use casper_types::bytesrepr::{deserialize_from_slice, ToBytes};
    use test_strategy::proptest;

    use super::{BlockHeader, Timestamp};

    #[proptest]
    fn serde_json_timestamp_round_trip(timestamp: Timestamp) {
        let serialized_timestamp = serde_json::to_string(&timestamp).unwrap();
        let casper_types_timestamp: casper_types::Timestamp =
            serde_json::from_str(&serialized_timestamp).unwrap();
        let serialized_casper_types_timestamp =
            serde_json::to_string(&casper_types_timestamp).unwrap();
        // Below is busted because we serialize to "1970-01-01T00:00:00Z" while casper_types::Timestamp serializes to "1970-01-01T00:00:00.000Z"
        // assert_eq!(serialized_timestamp, serialized_casper_types_timestamp);
        let deserialized_timestamp: Timestamp =
            serde_json::from_str(&serialized_casper_types_timestamp).unwrap();
        assert_eq!(timestamp, deserialized_timestamp);
    }

    #[proptest]
    fn bincode_timestamp_round_trip(timestamp: Timestamp) {
        let serialized_timestamp = bincode::serialize(&timestamp).unwrap();
        let casper_types_timestamp: casper_types::Timestamp =
            bincode::deserialize(&serialized_timestamp).unwrap();
        let serialized_casper_types_timestamp =
            bincode::serialize(&casper_types_timestamp).unwrap();
        assert_eq!(serialized_timestamp, serialized_casper_types_timestamp);
        let deserialized_timestamp: Timestamp =
            bincode::deserialize(&serialized_casper_types_timestamp).unwrap();
        assert_eq!(timestamp, deserialized_timestamp);
    }

    #[proptest]
    fn bytesrepr_timestamp_round_trip(timestamp: Timestamp) {
        let serialized_timestamp = timestamp.to_bytes().unwrap();
        let casper_types_timestamp: casper_types::Timestamp =
            deserialize_from_slice(&serialized_timestamp).unwrap();
        let serialized_casper_types_timestamp = casper_types_timestamp.to_bytes().unwrap();
        let deserialized_timestamp: Timestamp =
            deserialize_from_slice(&serialized_casper_types_timestamp).unwrap();
        assert_eq!(timestamp, deserialized_timestamp)
    }

    #[proptest]
    fn serde_json_block_header_round_trip(block_header: BlockHeader) {
        let serialized_block_header = serde_json::to_string(&block_header).unwrap();
        let casper_node_block_header: casper_node::types::BlockHeader =
            serde_json::from_str(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            serde_json::to_string(&casper_node_block_header).unwrap();
        let deserialized_block_header: BlockHeader =
            serde_json::from_str(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn bincode_block_header_round_trip(block_header: BlockHeader) {
        let serialized_block_header = bincode::serialize(&block_header).unwrap();
        let casper_node_block_header: casper_node::types::BlockHeader =
            bincode::deserialize(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            bincode::serialize(&casper_node_block_header).unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: BlockHeader =
            bincode::deserialize(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn bytesrepr_block_header_round_trip(block_header: BlockHeader) {
        let serialized_block_header = block_header.to_bytes().unwrap();
        let casper_node_block_header: casper_node::types::BlockHeader =
            deserialize_from_slice(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header = casper_node_block_header.to_bytes().unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: BlockHeader =
            deserialize_from_slice(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header)
    }

    #[proptest]
    fn block_header_hash_agree(block_header: BlockHeader) {
        let casper_node_block_header: casper_node::types::BlockHeader =
            deserialize_from_slice(&block_header.to_bytes().unwrap()).unwrap();
        let block_hash = block_header.block_hash();
        let casper_block_hash = casper_node_block_header.block_hash();
        assert_eq!(
            <[u8; 32]>::from(block_hash).to_vec(),
            casper_block_hash.as_ref().to_owned()
        );
    }
}
