#[cfg(test)]
use ed25519_dalek::Signer;

use casper_types::{PublicKey, Signature};
use k256::ecdsa::{signature::Verifier, VerifyingKey as Secp256k1PublicKey};

#[cfg(test)]
pub fn sign<T: AsRef<[u8]>>(secret_key: &casper_types::SecretKey, message: T) -> Signature {
    match secret_key {
        casper_types::SecretKey::System => Signature::System,
        casper_types::SecretKey::Ed25519(secret_key) => {
            let signature = secret_key.sign(message.as_ref());
            Signature::Ed25519(signature)
        }
        casper_types::SecretKey::Secp256k1(secret_key) => {
            let signature = secret_key
                .try_sign(message.as_ref())
                .expect("should create signature");
            Signature::Secp256k1(signature)
        }
        _ => panic!("SecretKey is marked as non-exhaustive, but this should never happen"),
    }
}

#[derive(Debug)]
pub enum SignatureVerificationError {
    SystemSignatureNotAllowed,
    FailedToVerifyEd25519Signature,
    FailedToVerifySecp256k1Signature,
    KeyTypeMismatch,
}

pub fn verify<T: AsRef<[u8]>>(
    public_key: &PublicKey,
    message: T,
    signature: &Signature,
) -> Result<(), SignatureVerificationError> {
    match (signature, public_key) {
        (Signature::System, _) => Err(SignatureVerificationError::SystemSignatureNotAllowed),
        (Signature::Ed25519(signature), PublicKey::Ed25519(public_key)) => public_key
            .verify_strict(message.as_ref(), signature)
            .map_err(|_| SignatureVerificationError::FailedToVerifyEd25519Signature),
        (Signature::Secp256k1(signature), PublicKey::Secp256k1(public_key)) => {
            let verifier: &Secp256k1PublicKey = public_key;
            verifier
                .verify(message.as_ref(), signature)
                .map_err(|_| SignatureVerificationError::FailedToVerifySecp256k1Signature)
        }
        _ => Err(SignatureVerificationError::KeyTypeMismatch),
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use casper_types::PublicKey as CasperPublicKey;
    use casper_types::SecretKey as CasperSecretKey;
    use ed25519_dalek::SigningKey as Ed25519SecretKey;
    use k256::ecdsa::SigningKey as Secp256k1SecretKey;
    use proptest::prelude::*;
    use test_strategy::proptest;

    use super::{sign, verify};

    #[derive(Debug)]
    enum RealSecretKey {
        Ed25519(Ed25519SecretKey),
        Secp256k1(Secp256k1SecretKey),
    }

    impl Arbitrary for RealSecretKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                any::<[u8; CasperPublicKey::ED25519_LENGTH]>()
                    .prop_map(|bytes| { RealSecretKey::Ed25519(Ed25519SecretKey::from(bytes)) }),
                any::<[u8; CasperSecretKey::SECP256K1_LENGTH]>()
                    .prop_filter("Cannot make a secret key from [0u8; 32]", |bytes| bytes
                        != &[0u8; CasperSecretKey::SECP256K1_LENGTH])
                    .prop_map(|bytes| RealSecretKey::Secp256k1(
                        Secp256k1SecretKey::from_slice(bytes.as_ref()).unwrap()
                    )),
            ]
            .boxed()
        }
    }

    impl From<RealSecretKey> for CasperSecretKey {
        fn from(real_secret_key: RealSecretKey) -> Self {
            match real_secret_key {
                RealSecretKey::Ed25519(ed25519_secret_key) => {
                    CasperSecretKey::Ed25519(ed25519_secret_key)
                }
                RealSecretKey::Secp256k1(secp256k1_secret_key) => {
                    CasperSecretKey::Secp256k1(secp256k1_secret_key)
                }
            }
        }
    }

    #[proptest]
    fn sign_and_verify(real_secret_key: RealSecretKey, message: Vec<u8>) {
        let casper_secret_key = CasperSecretKey::from(real_secret_key);
        let signature = sign(&casper_secret_key, &message);

        verify(
            &CasperPublicKey::from(&casper_secret_key),
            &message,
            &signature,
        )
        .unwrap();
    }

    #[proptest]
    fn signatures_should_agree_with_casper_types(real_secret_key: RealSecretKey, message: Vec<u8>) {
        let casper_secret_key = CasperSecretKey::from(real_secret_key);
        let our_signature = sign(&casper_secret_key, &message);
        let casper_types_signature = casper_types::crypto::sign(
            &message,
            &casper_secret_key,
            &CasperPublicKey::from(&casper_secret_key),
        );
        assert_eq!(our_signature, casper_types_signature)
    }

    #[test]
    fn should_not_verify_bad_ed25519_signature() {
        let bad_secret_key =
            CasperSecretKey::ed25519_from_bytes([0u8; CasperSecretKey::ED25519_LENGTH]).unwrap();
        let message = "this shouldn't work for the good public key";
        let bad_signature = sign(&bad_secret_key, message);
        verify(
            &CasperPublicKey::from(&bad_secret_key),
            message,
            &bad_signature,
        )
        .unwrap_or_else(|_| panic!("Bad secret key should be able to verify its own signature"));

        let good_public_key = CasperPublicKey::from(
            &CasperSecretKey::ed25519_from_bytes([1u8; CasperSecretKey::ED25519_LENGTH]).unwrap(),
        );
        assert!(
            verify(&good_public_key, message, &bad_signature).is_err(),
            "good public key should not be able to verify bad signature"
        )
    }

    #[test]
    fn should_not_verify_bad_secp256k1_signature() {
        // Can't use [0u8; 32] because its a bogus secret key
        let bad_secret_key =
            CasperSecretKey::secp256k1_from_bytes([1u8; CasperSecretKey::SECP256K1_LENGTH])
                .unwrap();
        let message = "this shouldn't work for the good public key";
        let bad_signature = sign(&bad_secret_key, message);

        verify(
            &CasperPublicKey::from(&bad_secret_key),
            message,
            &bad_signature,
        )
        .unwrap_or_else(|_| panic!("Bad secret key should be able to verify its own signature"));

        let good_public_key = CasperPublicKey::from(
            &CasperSecretKey::secp256k1_from_bytes([2u8; CasperSecretKey::SECP256K1_LENGTH])
                .unwrap(),
        );
        assert!(
            verify(&good_public_key, message, &bad_signature).is_err(),
            "good public key should not be able to verify bad signature"
        )
    }

    #[test]
    fn should_not_verify_system_signature() {
        let message = "system can't really sign anything";
        let bad_signature = sign(&CasperSecretKey::System, message);
        assert!(
            verify(&CasperPublicKey::System, message, &bad_signature).is_err(),
            "System is not allowed to sign anything"
        );
    }

    #[test]
    fn should_not_verify_different_signature_schemes() {
        let message = "should not work because the signatures are different types";
        let secret_bytes = [1u8; 32];
        let ed25519_secret_key = CasperSecretKey::ed25519_from_bytes(secret_bytes).unwrap();
        let secp256k1_public_key =
            CasperPublicKey::from(&CasperSecretKey::secp256k1_from_bytes(secret_bytes).unwrap());
        let ed25519_signature = sign(&ed25519_secret_key, message);
        assert!(
            verify(&secp256k1_public_key, message, &ed25519_signature).is_err(),
            "should not verify different types of public keys and signatures"
        )
    }
}
