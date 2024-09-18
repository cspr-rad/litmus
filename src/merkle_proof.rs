// See https://github.com/casper-network/casper-node/blob/76ea7104cda02fcf1bd6edb686fd00b162dabde8/execution_engine/src/storage/trie/mod.rs
// and https://github.com/casper-network/casper-node/blob/76ea7104cda02fcf1bd6edb686fd00b162dabde8/execution_engine/src/storage/trie/merkle_proof.rs

use casper_storage::global_state::trie_store::operations::compute_state_hash;
pub use casper_types::global_state::TrieMerkleProofStep;

use casper_types::{bytesrepr, CLValueError, Digest, Key, StoredValue};

pub type TrieMerkleProof = casper_types::global_state::TrieMerkleProof<Key, StoredValue>;

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
    proofs: &'a [TrieMerkleProof],
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
