use alloc::{string::String, vec::Vec};
use casper_types::bytesrepr::{FromBytes, ToBytes};
use proptest_derive::Arbitrary;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const DIGEST_LENGTH: usize = 32;

#[derive(Arbitrary, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/hashing/src/lib.rs#L48
pub struct Digest([u8; DIGEST_LENGTH]);

impl Digest {
    pub fn hash(data: &[u8]) -> Self {
        let hashed_data: [u8; DIGEST_LENGTH] = blake2b_simd::Params::new()
            .hash_length(DIGEST_LENGTH)
            .hash(data)
            .as_bytes()
            .try_into()
            .unwrap_or_else(|_| panic!("should be {} bytes long", DIGEST_LENGTH));
        Digest(hashed_data)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Digest> for [u8; DIGEST_LENGTH] {
    fn from(digest: Digest) -> Self {
        digest.0
    }
}

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(bytes: [u8; DIGEST_LENGTH]) -> Self {
        Digest(bytes)
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/hashing/src/lib.rs#L316-L339
impl ToBytes for Digest {
    fn to_bytes(&self) -> Result<Vec<u8>, casper_types::bytesrepr::Error> {
        self.0.to_bytes()
    }

    fn serialized_length(&self) -> usize {
        self.0.serialized_length()
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), casper_types::bytesrepr::Error> {
        writer.extend_from_slice(&self.0);
        Ok(())
    }
}

impl FromBytes for Digest {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), casper_types::bytesrepr::Error> {
        FromBytes::from_bytes(bytes).map(|(arr, rem)| (Digest(arr), rem))
    }
}

// See: https://github.com/casper-network/casper-node/blob/8ca9001dabba0dae95f92ad8c54eddd163200b5d/hashing/src/lib.rs#L341-L367
impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            base16::encode_lower(&self.0).serialize(serializer)
        } else {
            self.0[..].serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8>;

        if deserializer.is_human_readable() {
            let hex_string = String::deserialize(deserializer)?;
            bytes = base16::decode(hex_string.as_bytes()).map_err(serde::de::Error::custom)?;
        } else {
            bytes = <Vec<u8>>::deserialize(deserializer)?;
        }

        let data =
            <[u8; DIGEST_LENGTH]>::try_from(bytes.as_ref()).map_err(serde::de::Error::custom)?;
        Ok(Digest(data))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec::Vec;
    use casper_types::bytesrepr::{deserialize_from_slice, ToBytes};
    use test_strategy::proptest;

    use super::{Digest, DIGEST_LENGTH};

    #[proptest]
    fn serde_json_digest_round_trip(timestamp: Digest) {
        let serialized_digest = serde_json::to_string(&timestamp).unwrap();
        let casper_hashing_digest: casper_hashing::Digest =
            serde_json::from_str(&serialized_digest).unwrap();
        let serialized_casper_hashing_digest =
            serde_json::to_string(&casper_hashing_digest).unwrap();
        assert_eq!(serialized_digest, serialized_casper_hashing_digest);
        let deserialized_digest: Digest =
            serde_json::from_str(&serialized_casper_hashing_digest).unwrap();
        assert_eq!(timestamp, deserialized_digest);
    }

    #[proptest]
    fn bincode_timestamp_round_trip(timestamp: Digest) {
        let serialized_timestamp = bincode::serialize(&timestamp).unwrap();
        let casper_types_timestamp: casper_hashing::Digest =
            bincode::deserialize(&serialized_timestamp).unwrap();
        let serialized_casper_types_timestamp =
            bincode::serialize(&casper_types_timestamp).unwrap();
        assert_eq!(serialized_timestamp, serialized_casper_types_timestamp);
        let deserialized_timestamp: Digest =
            bincode::deserialize(&serialized_casper_types_timestamp).unwrap();
        assert_eq!(timestamp, deserialized_timestamp);
    }

    #[proptest]
    fn bytesrepr_digest_round_trip(digest: Digest) {
        let serialized_digest = digest.to_bytes().unwrap();
        let casper_hashing_digest: casper_hashing::Digest =
            deserialize_from_slice(&serialized_digest).unwrap();
        let serialized_casper_hashing_digest = casper_hashing_digest.to_bytes().unwrap();
        let deserialized_digest: Digest =
            deserialize_from_slice(&serialized_casper_hashing_digest).unwrap();
        assert_eq!(digest, deserialized_digest)
    }

    #[proptest]
    fn hashing_agrees_with_casper_hashing(data: Vec<u8>) {
        let digest = Digest::hash(&data);
        let casper_digest = casper_hashing::Digest::hash(&data);
        assert_eq!(
            <[u8; DIGEST_LENGTH]>::from(digest),
            <[u8; DIGEST_LENGTH]>::from(casper_digest)
        );
    }
}
