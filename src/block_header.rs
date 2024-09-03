use alloc::{string::String, vec::Vec};

#[cfg(test)]
use proptest::{arbitrary::Arbitrary, prelude::*};

use casper_types::bytesrepr::{self, FromBytes, ToBytes};
use casper_types::{EraId, ProtocolVersion, PublicKey};
use time::OffsetDateTime;

use crate::consensus::EraEndV2;

use super::consensus::EraEndV1;
use super::hash::Digest;
use super::hash::DIGEST_LENGTH;

#[derive(
    Clone, Default, Ord, PartialOrd, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L648
pub struct BlockHash(Digest);

impl BlockHash {
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

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

#[cfg(test)]
impl Arbitrary for Timestamp {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (0u64..=253402300799).prop_map(Timestamp).boxed()
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
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

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub enum BlockHeader {
    /// The legacy, initial version of the header portion of a block.
    #[cfg_attr(test, serde(rename = "Version1"))]
    V1(BlockHeaderV1),
    /// The version 2 of the header portion of a block.
    #[cfg_attr(test, serde(rename = "Version2"))]
    V2(BlockHeaderV2),
}

/// Tag for block header v1.
pub const BLOCK_HEADER_V1_TAG: u8 = 0;
/// Tag for block header v2.
pub const BLOCK_HEADER_V2_TAG: u8 = 1;

impl BlockHeader {
    /// Returns the hash of this block header.
    pub fn block_hash(&self) -> BlockHash {
        match self {
            BlockHeader::V1(v1) => v1.block_hash(),
            BlockHeader::V2(v2) => v2.block_hash(),
        }
    }

    /// Returns the parent block's hash.
    pub fn parent_hash(&self) -> &BlockHash {
        match self {
            BlockHeader::V1(v1) => v1.parent_hash(),
            BlockHeader::V2(v2) => v2.parent_hash(),
        }
    }

    /// Returns the root hash of global state after the deploys in this block have been executed.
    pub fn state_root_hash(&self) -> &Digest {
        match self {
            BlockHeader::V1(v1) => v1.state_root_hash(),
            BlockHeader::V2(v2) => v2.state_root_hash(),
        }
    }

    /// Returns the hash of the block's body.
    pub fn body_hash(&self) -> &Digest {
        match self {
            BlockHeader::V1(v1) => v1.body_hash(),
            BlockHeader::V2(v2) => v2.body_hash(),
        }
    }

    /// Returns a random bit needed for initializing a future era.
    pub fn random_bit(&self) -> bool {
        match self {
            BlockHeader::V1(v1) => v1.random_bit(),
            BlockHeader::V2(v2) => v2.random_bit(),
        }
    }

    /// Returns a seed needed for initializing a future era.
    pub fn accumulated_seed(&self) -> &Digest {
        match self {
            BlockHeader::V1(v1) => v1.accumulated_seed(),
            BlockHeader::V2(v2) => v2.accumulated_seed(),
        }
    }

    /// Returns the timestamp from when the block was proposed.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            BlockHeader::V1(v1) => v1.timestamp(),
            BlockHeader::V2(v2) => v2.timestamp(),
        }
    }

    /// Returns the era ID in which this block was created.
    pub fn era_id(&self) -> EraId {
        match self {
            BlockHeader::V1(v1) => v1.era_id(),
            BlockHeader::V2(v2) => v2.era_id(),
        }
    }

    /// Returns the height of this block, i.e. the number of ancestors.
    pub fn height(&self) -> u64 {
        match self {
            BlockHeader::V1(v1) => v1.height(),
            BlockHeader::V2(v2) => v2.height(),
        }
    }

    /// Returns the protocol version of the network from when this block was created.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match self {
            BlockHeader::V1(v1) => v1.protocol_version(),
            BlockHeader::V2(v2) => v2.protocol_version(),
        }
    }
}

impl From<BlockHeaderV1> for BlockHeader {
    fn from(header: BlockHeaderV1) -> Self {
        BlockHeader::V1(header)
    }
}

impl From<BlockHeaderV2> for BlockHeader {
    fn from(header: BlockHeaderV2) -> Self {
        BlockHeader::V2(header)
    }
}

impl ToBytes for BlockHeader {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        match self {
            BlockHeader::V1(v1) => {
                buffer.insert(0, BLOCK_HEADER_V1_TAG);
                buffer.extend(v1.to_bytes()?);
            }
            BlockHeader::V2(v2) => {
                buffer.insert(0, BLOCK_HEADER_V2_TAG);
                buffer.extend(v2.to_bytes()?);
            }
        }
        Ok(buffer)
    }

    fn serialized_length(&self) -> usize {
        1 + match self {
            BlockHeader::V1(v1) => v1.serialized_length(),
            BlockHeader::V2(v2) => v2.serialized_length(),
        }
    }
}

impl FromBytes for BlockHeader {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, remainder) = u8::from_bytes(bytes)?;
        match tag {
            BLOCK_HEADER_V1_TAG => {
                let (header, remainder): (BlockHeaderV1, _) = FromBytes::from_bytes(remainder)?;
                Ok((Self::V1(header), remainder))
            }
            BLOCK_HEADER_V2_TAG => {
                let (header, remainder): (BlockHeaderV2, _) = FromBytes::from_bytes(remainder)?;
                Ok((Self::V2(header), remainder))
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

#[cfg(test)]
impl Arbitrary for BlockHeader {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<BlockHeaderV1>().prop_map(BlockHeader::V1),
            any::<BlockHeaderV2>().prop_map(BlockHeader::V2),
        ]
        .boxed()
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/node/src/types/block.rs#L813-L828
pub struct BlockHeaderV1 {
    parent_hash: BlockHash,
    state_root_hash: Digest,
    body_hash: Digest,
    random_bit: bool,
    accumulated_seed: Digest,
    era_end: Option<EraEndV1>,
    timestamp: Timestamp,
    era_id: EraId,
    height: u64,
    protocol_version: ProtocolVersion,
}

impl BlockHeaderV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_hash: BlockHash,
        state_root_hash: Digest,
        body_hash: Digest,
        random_bit: bool,
        accumulated_seed: Digest,
        era_end: Option<EraEndV1>,
        timestamp: Timestamp,
        era_id: EraId,
        height: u64,
        protocol_version: ProtocolVersion,
    ) -> Self {
        BlockHeaderV1 {
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

    pub fn era_end(&self) -> Option<&EraEndV1> {
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

#[cfg(test)]
fn arb_protocolversion() -> impl Strategy<Value = ProtocolVersion> {
    (0..=255u32, 0..=255u32, 0..=255u32)
        .prop_map(|(major, minor, patch)| ProtocolVersion::from_parts(major, minor, patch))
}

#[cfg(test)]
impl Arbitrary for BlockHeaderV1 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            any::<BlockHash>(),
            any::<Digest>(),
            any::<Digest>(),
            any::<bool>(),
            any::<Digest>(),
            any::<Option<EraEndV1>>(),
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
                    BlockHeaderV1 {
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

impl ToBytes for BlockHeaderV1 {
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

impl FromBytes for BlockHeaderV1 {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        let (parent_hash, remainder) = BlockHash::from_bytes(bytes)?;
        let (state_root_hash, remainder) = Digest::from_bytes(remainder)?;
        let (body_hash, remainder) = Digest::from_bytes(remainder)?;
        let (random_bit, remainder) = bool::from_bytes(remainder)?;
        let (accumulated_seed, remainder) = Digest::from_bytes(remainder)?;
        let (era_end, remainder) = Option::<EraEndV1>::from_bytes(remainder)?;
        let (timestamp, remainder) = Timestamp::from_bytes(remainder)?;
        let (era_id, remainder) = EraId::from_bytes(remainder)?;
        let (height, remainder) = u64::from_bytes(remainder)?;
        let (protocol_version, remainder) = ProtocolVersion::from_bytes(remainder)?;
        let block_header = BlockHeaderV1 {
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

/// The header portion of a block.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize, serde::Deserialize))]
pub struct BlockHeaderV2 {
    /// The parent block's hash.
    pub parent_hash: BlockHash,
    /// The root hash of global state after the deploys in this block have been executed.
    pub state_root_hash: Digest,
    /// The hash of the block's body.
    pub body_hash: Digest,
    /// A random bit needed for initializing a future era.
    pub random_bit: bool,
    /// A seed needed for initializing a future era.
    pub accumulated_seed: Digest,
    /// The `EraEnd` of a block if it is a switch block.
    pub era_end: Option<EraEndV2>,
    /// The timestamp from when the block was proposed.
    pub timestamp: Timestamp,
    /// The era ID in which this block was created.
    pub era_id: EraId,
    /// The height of this block, i.e. the number of ancestors.
    pub height: u64,
    /// The protocol version of the network from when this block was created.
    pub protocol_version: ProtocolVersion,
    /// The public key of the validator which proposed the block.
    pub proposer: PublicKey,
    /// The gas price of the era
    pub current_gas_price: u8,
    /// The most recent switch block hash.
    pub last_switch_block_hash: Option<BlockHash>,
}

impl BlockHeaderV2 {
    /// Returns the hash of this block header.
    pub fn block_hash(&self) -> BlockHash {
        self.compute_block_hash()
    }

    /// Returns the parent block's hash.
    pub fn parent_hash(&self) -> &BlockHash {
        &self.parent_hash
    }

    /// Returns the root hash of global state after the deploys in this block have been executed.
    pub fn state_root_hash(&self) -> &Digest {
        &self.state_root_hash
    }

    /// Returns the hash of the block's body.
    pub fn body_hash(&self) -> &Digest {
        &self.body_hash
    }

    /// Returns a random bit needed for initializing a future era.
    pub fn random_bit(&self) -> bool {
        self.random_bit
    }

    /// Returns a seed needed for initializing a future era.
    pub fn accumulated_seed(&self) -> &Digest {
        &self.accumulated_seed
    }

    /// Returns the `EraEnd` of a block if it is a switch block.
    pub fn era_end(&self) -> Option<&EraEndV2> {
        self.era_end.as_ref()
    }

    /// Returns the timestamp from when the block was proposed.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    /// Returns the era ID in which this block was created.
    pub fn era_id(&self) -> EraId {
        self.era_id
    }

    /// Returns the era ID in which the next block would be created (i.e. this block's era ID, or
    /// its successor if this is a switch block).
    pub fn next_block_era_id(&self) -> EraId {
        if self.era_end.is_some() {
            self.era_id.successor()
        } else {
            self.era_id
        }
    }

    /// Returns the height of this block, i.e. the number of ancestors.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Returns the protocol version of the network from when this block was created.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns `true` if this block is the last one in the current era.
    pub fn is_switch_block(&self) -> bool {
        self.era_end.is_some()
    }

    /// Returns the public key of the validator which proposed the block.
    pub fn proposer(&self) -> &PublicKey {
        &self.proposer
    }

    /// Returns `true` if this block is the Genesis block, i.e. has height 0 and era 0.
    pub fn is_genesis(&self) -> bool {
        self.era_id().is_genesis() && self.height() == 0
    }

    /// Returns the gas price for the given block.
    pub fn current_gas_price(&self) -> u8 {
        self.current_gas_price
    }

    pub(crate) fn compute_block_hash(&self) -> BlockHash {
        let serialized_header = self
            .to_bytes()
            .unwrap_or_else(|error| panic!("should serialize block header: {}", error));
        BlockHash::from(Digest::hash(&serialized_header))
    }
}

impl ToBytes for BlockHeaderV2 {
    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        self.parent_hash.write_bytes(writer)?;
        self.state_root_hash.write_bytes(writer)?;
        self.body_hash.write_bytes(writer)?;
        self.random_bit.write_bytes(writer)?;
        self.accumulated_seed.write_bytes(writer)?;
        self.era_end.write_bytes(writer)?;
        self.timestamp.write_bytes(writer)?;
        self.era_id.write_bytes(writer)?;
        self.height.write_bytes(writer)?;
        self.protocol_version.write_bytes(writer)?;
        self.proposer.write_bytes(writer)?;
        self.current_gas_price.write_bytes(writer)?;
        self.last_switch_block_hash.write_bytes(writer)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut buffer = bytesrepr::allocate_buffer(self)?;
        self.write_bytes(&mut buffer)?;
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
            + self.proposer.serialized_length()
            + self.current_gas_price.serialized_length()
            + self.last_switch_block_hash.serialized_length()
    }
}

impl FromBytes for BlockHeaderV2 {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (parent_hash, remainder) = BlockHash::from_bytes(bytes)?;
        let (state_root_hash, remainder) = Digest::from_bytes(remainder)?;
        let (body_hash, remainder) = Digest::from_bytes(remainder)?;
        let (random_bit, remainder) = bool::from_bytes(remainder)?;
        let (accumulated_seed, remainder) = Digest::from_bytes(remainder)?;
        let (era_end, remainder) = Option::from_bytes(remainder)?;
        let (timestamp, remainder) = Timestamp::from_bytes(remainder)?;
        let (era_id, remainder) = EraId::from_bytes(remainder)?;
        let (height, remainder) = u64::from_bytes(remainder)?;
        let (protocol_version, remainder) = ProtocolVersion::from_bytes(remainder)?;
        let (proposer, remainder) = PublicKey::from_bytes(remainder)?;
        let (current_gas_price, remainder) = u8::from_bytes(remainder)?;
        let (last_switch_block_hash, remainder) = Option::from_bytes(remainder)?;
        let block_header = BlockHeaderV2 {
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
            proposer,
            current_gas_price,
            last_switch_block_hash,
        };
        Ok((block_header, remainder))
    }
}

#[cfg(test)]
impl Arbitrary for BlockHeaderV2 {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        (
            // this tuple is needed because prop_map only supports tuples of arity <= 12
            (any::<BlockHash>(), any::<Digest>()),
            any::<Digest>(),
            any::<bool>(),
            any::<Digest>(),
            any::<Option<EraEndV2>>(),
            any::<Timestamp>(),
            any::<u64>(),
            any::<u64>(),
            arb_protocolversion(),
            casper_types::crypto::gens::public_key_arb(),
            0..=255u8,
            any::<Option<BlockHash>>(),
        )
            .prop_map(
                |(
                    (parent_hash, state_root_hash),
                    body_hash,
                    random_bit,
                    accumulated_seed,
                    era_end,
                    timestamp,
                    era_id,
                    height,
                    protocol_version,
                    proposer,
                    current_gas_price,
                    last_switch_block_hash,
                )| {
                    let era_id = EraId::from(era_id);
                    BlockHeaderV2 {
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
                        proposer,
                        current_gas_price,
                        last_switch_block_hash,
                    }
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use alloc::borrow::ToOwned;
    use casper_types::bytesrepr::{deserialize_from_slice, ToBytes};
    use test_strategy::proptest;

    use super::{BlockHeaderV1, Timestamp};

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
    fn serde_json_block_header_v1_round_trip(block_header: BlockHeaderV1) {
        let serialized_block_header = serde_json::to_string(&block_header).unwrap();
        let casper_node_block_header: casper_types::BlockHeaderV1 =
            serde_json::from_str(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            serde_json::to_string(&casper_node_block_header).unwrap();
        let deserialized_block_header: BlockHeaderV1 =
            serde_json::from_str(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn serde_json_block_header_round_trip(block_header: super::BlockHeader) {
        let serialized_block_header = serde_json::to_string(&block_header).unwrap();
        let casper_node_block_header: casper_types::BlockHeader =
            serde_json::from_str(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            serde_json::to_string(&casper_node_block_header).unwrap();
        let deserialized_block_header: super::BlockHeader =
            serde_json::from_str(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn bincode_block_header_v1_round_trip(block_header: BlockHeaderV1) {
        let serialized_block_header = bincode::serialize(&block_header).unwrap();
        let casper_node_block_header: casper_types::BlockHeaderV1 =
            bincode::deserialize(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            bincode::serialize(&casper_node_block_header).unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: BlockHeaderV1 =
            bincode::deserialize(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn bincode_block_header_round_trip(block_header: super::BlockHeader) {
        let serialized_block_header = bincode::serialize(&block_header).unwrap();
        let casper_node_block_header: casper_types::BlockHeader =
            bincode::deserialize(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header =
            bincode::serialize(&casper_node_block_header).unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: super::BlockHeader =
            bincode::deserialize(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header);
    }

    #[proptest]
    fn bytesrepr_block_header_v1_round_trip(block_header: BlockHeaderV1) {
        let serialized_block_header = block_header.to_bytes().unwrap();
        let casper_node_block_header: casper_types::BlockHeaderV1 =
            deserialize_from_slice(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header = casper_node_block_header.to_bytes().unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: BlockHeaderV1 =
            deserialize_from_slice(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header)
    }

    #[proptest]
    fn bytesrepr_block_header_round_trip(block_header: super::BlockHeader) {
        let serialized_block_header = block_header.to_bytes().unwrap();
        let casper_node_block_header: casper_types::BlockHeader =
            deserialize_from_slice(&serialized_block_header).unwrap();
        let serialized_casper_node_block_header = casper_node_block_header.to_bytes().unwrap();
        assert_eq!(serialized_block_header, serialized_casper_node_block_header);
        let deserialized_block_header: super::BlockHeader =
            deserialize_from_slice(&serialized_casper_node_block_header).unwrap();
        assert_eq!(block_header, deserialized_block_header)
    }

    #[proptest]
    fn block_header_v1_hash_agree(block_header: BlockHeaderV1) {
        let casper_node_block_header: casper_types::BlockHeaderV1 =
            deserialize_from_slice(block_header.to_bytes().unwrap()).unwrap();
        let block_hash = block_header.block_hash();
        let casper_block_hash = casper_node_block_header.block_hash();
        assert_eq!(
            <[u8; 32]>::from(block_hash).to_vec(),
            casper_block_hash.as_ref().to_owned()
        );
    }

    #[proptest]
    fn block_header_hash_agree(block_header: super::BlockHeader) {
        let casper_node_block_header: casper_types::BlockHeader =
            deserialize_from_slice(block_header.to_bytes().unwrap()).unwrap();
        let block_hash = block_header.block_hash();
        let casper_block_hash = casper_node_block_header.block_hash();
        assert_eq!(
            <[u8; 32]>::from(block_hash).to_vec(),
            casper_block_hash.as_ref().to_owned()
        );
    }
}
