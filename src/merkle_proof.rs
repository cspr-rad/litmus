// See https://github.com/casper-network/casper-node/blob/76ea7104cda02fcf1bd6edb686fd00b162dabde8/execution_engine/src/storage/trie/mod.rs
// and https://github.com/casper-network/casper-node/blob/76ea7104cda02fcf1bd6edb686fd00b162dabde8/execution_engine/src/storage/trie/merkle_proof.rs
use core::mem::MaybeUninit;

use std::{boxed::Box, string::String, vec::Vec};

use casper_storage::global_state::trie_store::operations::compute_state_hash;
pub use casper_types::global_state::{TrieMerkleProof, TrieMerkleProofStep};

use casper_types::{
    bytesrepr::{self, Bytes, FromBytes, ToBytes, U8_SERIALIZED_LENGTH},
    CLValueError, Digest, Key, StoredValue,
};
#[cfg(test)]
use proptest::prelude::*;

use super::hash::DIGEST_LENGTH;

const RADIX: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pointer {
    LeafPointer(Digest),
    NodePointer(Digest),
}

impl Pointer {
    pub fn hash(&self) -> &Digest {
        match self {
            Pointer::LeafPointer(hash) => hash,
            Pointer::NodePointer(hash) => hash,
        }
    }
}

#[cfg(test)]
impl Arbitrary for Pointer {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            any::<[u8; DIGEST_LENGTH]>().prop_map(|h| Pointer::LeafPointer(Digest::from_raw(h))),
            any::<[u8; DIGEST_LENGTH]>().prop_map(|h| Pointer::NodePointer(Digest::from_raw(h))),
        ]
        .boxed()
    }
}

impl ToBytes for Pointer {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::unchecked_allocate_buffer(self);
        self.write_bytes(&mut ret)?;
        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        U8_SERIALIZED_LENGTH + DIGEST_LENGTH
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        let tag: u8 = match self {
            Pointer::LeafPointer(_) => 0,
            Pointer::NodePointer(_) => 1,
        };
        writer.push(tag);
        writer.extend_from_slice(self.hash().as_ref());
        Ok(())
    }
}

impl FromBytes for Pointer {
    fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let (tag, rem) = u8::from_bytes(bytes)?;
        match tag {
            0 => {
                let (hash, rem) = Digest::from_bytes(rem)?;
                Ok((Pointer::LeafPointer(hash), rem))
            }
            1 => {
                let (hash, rem) = Digest::from_bytes(rem)?;
                Ok((Pointer::NodePointer(hash), rem))
            }
            _ => Err(bytesrepr::Error::Formatting),
        }
    }
}

pub type PointerBlockValue = Option<Pointer>;

pub type PointerBlockArray = [PointerBlockValue; RADIX];

#[derive(Debug, PartialEq, Eq, Clone)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
pub struct PointerBlock(PointerBlockArray);

impl Default for PointerBlock {
    fn default() -> Self {
        Self::new()
    }
}

impl PointerBlock {
    pub fn new() -> Self {
        PointerBlock([
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None,
        ])
    }

    pub fn from_indexed_pointers(indexed_pointers: &[(u8, Pointer)]) -> Self {
        let PointerBlock(mut pointer_block_array) = PointerBlock::new();
        for (idx, ptr) in indexed_pointers.iter() {
            pointer_block_array[*idx as usize] = Some(ptr.clone());
        }
        PointerBlock(pointer_block_array)
    }
}

impl ToBytes for PointerBlock {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut result = bytesrepr::allocate_buffer(self)?;
        for pointer in self.0.iter() {
            result.append(&mut pointer.to_bytes()?);
        }
        Ok(result)
    }

    fn serialized_length(&self) -> usize {
        self.0.iter().map(ToBytes::serialized_length).sum()
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        for pointer in self.0.iter() {
            pointer.write_bytes(writer)?;
        }
        Ok(())
    }
}

impl FromBytes for PointerBlock {
    fn from_bytes(mut bytes: &[u8]) -> Result<(Self, &[u8]), bytesrepr::Error> {
        let pointer_block_array = {
            // With MaybeUninit here we can avoid default initialization of result array below.
            let mut result: MaybeUninit<PointerBlockArray> = MaybeUninit::uninit();
            let result_ptr = result.as_mut_ptr() as *mut PointerBlockValue;
            for i in 0..RADIX {
                let (t, remainder) = match FromBytes::from_bytes(bytes) {
                    Ok(success) => success,
                    Err(error) => {
                        for j in 0..i {
                            unsafe { result_ptr.add(j).drop_in_place() }
                        }
                        return Err(error);
                    }
                };
                unsafe { result_ptr.add(i).write(t) };
                bytes = remainder;
            }
            unsafe { result.assume_init() }
        };
        Ok((PointerBlock(pointer_block_array), bytes))
    }
}

// FIXME not sure if this is used anywhere?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trie {
    Leaf { key: Key, value: StoredValue },
    Node { pointer_block: Box<PointerBlock> },
    Extension { affix: Bytes, pointer: Pointer },
}

impl Trie {
    pub fn trie_hash(&self) -> Result<Digest, bytesrepr::Error> {
        self.to_bytes()
            .map(|bytes| Digest::hash_into_chunks_if_necessary(&bytes))
    }

    pub fn node(indexed_pointers: &[(u8, Pointer)]) -> Self {
        let pointer_block = PointerBlock::from_indexed_pointers(indexed_pointers);
        let pointer_block = Box::new(pointer_block);
        Trie::Node { pointer_block }
    }

    pub fn extension(affix: Vec<u8>, pointer: Pointer) -> Self {
        Trie::Extension {
            affix: affix.into(),
            pointer,
        }
    }
}

#[cfg(test)]
impl Arbitrary for Trie {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            (
                casper_types::gens::key_arb(),
                casper_types::gens::stored_value_arb()
            )
                .prop_map(|(key, value)| Trie::Leaf { key, value }),
            any::<PointerBlock>().prop_map(|pointer_block| Trie::Node {
                pointer_block: Box::new(pointer_block)
            }),
            (
                proptest::collection::vec(any::<u8>(), 0..32),
                any::<Pointer>()
            )
                .prop_map(|(affix, pointer)| Trie::Extension {
                    affix: affix.into(),
                    pointer,
                })
        ]
        .boxed()
    }
}

impl ToBytes for Trie {
    fn to_bytes(&self) -> Result<Vec<u8>, bytesrepr::Error> {
        let mut ret = bytesrepr::allocate_buffer(self)?;
        self.write_bytes(&mut ret)?;
        Ok(ret)
    }

    fn serialized_length(&self) -> usize {
        U8_SERIALIZED_LENGTH
            + match self {
                Trie::Leaf { key, value } => key.serialized_length() + value.serialized_length(),
                Trie::Node { pointer_block } => pointer_block.serialized_length(),
                Trie::Extension { affix, pointer } => {
                    affix.serialized_length() + pointer.serialized_length()
                }
            }
    }

    fn write_bytes(&self, writer: &mut Vec<u8>) -> Result<(), bytesrepr::Error> {
        match self {
            Trie::Leaf { key, value } => {
                writer.push(0u8);
                key.write_bytes(writer)?;
                value.write_bytes(writer)?;
            }
            Trie::Node { pointer_block } => {
                writer.push(1u8);
                pointer_block.write_bytes(writer)?
            }
            Trie::Extension { affix, pointer } => {
                writer.push(2u8);
                affix.write_bytes(writer)?;
                pointer.write_bytes(writer)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    PathLengthDifferentThanProofLessOne,
    UnexpectedKey,
    UnexpectedValue,
    InvalidProofHash,
    PathCold,
    BytesRepr(bytesrepr::Error),
    KeyIsNotAURef(Key),
    ValueToCLValueConversion,
    CLValueError(CLValueError),
}

impl From<CLValueError> for ValidationError {
    fn from(err: CLValueError) -> Self {
        ValidationError::CLValueError(err)
    }
}

impl From<bytesrepr::Error> for ValidationError {
    fn from(error: bytesrepr::Error) -> Self {
        Self::BytesRepr(error)
    }
}

pub struct QueryInfo<'a, 'b> {
    state_root: Digest,
    key: &'a Key,
    stored_value: &'b StoredValue,
}

impl<'a, 'b> QueryInfo<'a, 'b> {
    pub fn state_root(&self) -> &Digest {
        &self.state_root
    }

    pub fn key(&self) -> &'a Key {
        self.key
    }

    pub fn stored_value(&self) -> &'b StoredValue {
        self.stored_value
    }
}

pub fn process_query_proofs<'a>(
    proofs: &'a [TrieMerkleProof<Key, StoredValue>],
    path: &[String],
) -> Result<QueryInfo<'a, 'a>, ValidationError> {
    if proofs.len() != path.len() + 1 {
        return Err(ValidationError::PathLengthDifferentThanProofLessOne);
    }

    let mut proofs_iter = proofs.iter();

    // length check above means we are safe to unwrap here
    let first_proof = proofs_iter.next().unwrap();

    let state_root = compute_state_hash(first_proof)?;

    let mut proof_value = first_proof.value();

    for (proof, path_component) in proofs_iter.zip(path.iter()) {
        let named_keys = match proof_value {
            StoredValue::Account(account) => account.named_keys(),
            StoredValue::Contract(contract) => contract.named_keys(),
            _ => return Err(ValidationError::PathCold),
        };

        let key = match named_keys.get(path_component) {
            Some(key) => key,
            None => return Err(ValidationError::PathCold),
        };

        if proof.key() != &key.normalize() {
            return Err(ValidationError::UnexpectedKey);
        }

        if state_root != compute_state_hash(proof)? {
            return Err(ValidationError::InvalidProofHash);
        }

        proof_value = proof.value();
    }

    Ok(QueryInfo {
        state_root,
        key: first_proof.key(),
        stored_value: proof_value,
    })
}
