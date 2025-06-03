use pyo3::{
    prelude::*,
    types::PyBytes
};
use std::collections::HashMap;
use frost_evm::{
    self,
    frost_core::{
        self,
        Challenge,
        compute_group_commitment,
        compute_binding_factor_list,
    },
    frost_secp256k1::Secp256K1Sha256,
    keys, round1, round2, Identifier, SigningPackage, Error
};
use hex;

use crate::secp256k1::{
    num_to_id,
    keypair_new,
    get_pubkey,
    single_sign,
    single_verify,
    keys_split,
    keys_generate_with_dealer,
    dkg_part1,
    verify_proof_of_knowledge,
    dkg_part2,
    dkg_verify_secret_share,
    dkg_part3,
    keys_reconstruct,
    key_package_from,
    round1_commit,
    signing_package_new,
    // round2_sign,
    // verify_share,
    // aggregate,
    pubkey_tweak,
    pubkey_package_tweak,
    key_package_tweak,
    // verify_group_signature
};

use crate::common::macros::RET_ERR;
mod structs;
mod utils;


#[pyfunction]
pub fn round2_sign(py: Python, signing_package: &PyAny, signer_nonces: &PyAny, key_package: &PyAny) -> PyResult<PyObject> {
	let signing_package: SigningPackage = utils::from_pydict(signing_package)?;
	let signer_nonces: round1::SigningNonces = utils::from_pydict(signer_nonces)?;
	let key_package: keys::KeyPackage = utils::from_pydict(key_package)?;
	let signature_share: round2::SignatureShare = RET_ERR!(
        frost_evm::round2::sign(&signing_package, &signer_nonces, &key_package)
    );
	utils::to_pydict(py, &signature_share)
}

fn make_challange(
    signing_package: SigningPackage,
    verifying_key: frost_core::VerifyingKey<Secp256K1Sha256>
) -> Result<Challenge<Secp256K1Sha256>, Error>{
    let group_public = frost_evm::VerifyingKey::new(verifying_key.to_element());

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list =
        compute_binding_factor_list(&signing_package, &verifying_key, &[]);

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = compute_group_commitment(&signing_package, &binding_factor_list)?;

    let challenge = Challenge::from_scalar(group_public.challenge(
        frost_evm::VerifyingKey::message_hash(signing_package.message().as_slice()),
        group_commitment.to_element(),
    ));

    Ok(challenge)
}

#[pyfunction]
pub fn verify_share(
    py: Python,
	identifier: &PyAny,
	verifying_share: &PyAny,
	signature_share: &PyAny,
	signing_package: &PyAny,
	verifying_key: &PyAny
) -> PyResult<PyObject> {
	let identifier: Identifier = utils::from_pydict(identifier)?;
	let verifying_share: frost_core::keys::VerifyingShare<Secp256K1Sha256> =
        utils::from_pydict(verifying_share)?;
	let signature_share: round2::SignatureShare = utils::from_pydict(signature_share)?;
	let signing_package: SigningPackage = utils::from_pydict(signing_package)?;
	let verifying_key: frost_core::VerifyingKey<Secp256K1Sha256> =
        utils::from_pydict(verifying_key)?;

    // Encodes the signing commitment list produced in round one as part of generating [`BindingFactor`], the
    // binding factor.
    let binding_factor_list =
        frost_core::compute_binding_factor_list(&signing_package, &verifying_key, &[]);

    // Compute Lagrange coefficient.
    let lambda_i = RET_ERR!(frost_core::derive_interpolating_value(&identifier, &signing_package));

    let binding_factor = RET_ERR!(
        binding_factor_list.get(&identifier).ok_or(Error::UnknownIdentifier)
    ).clone();

    // Compute the commitment share.
    let r_share = RET_ERR!(
        signing_package.signing_commitment(&identifier).ok_or(Error::UnknownIdentifier)
    )
        .to_group_commitment_share(&binding_factor);

    let challenge = RET_ERR!(make_challange(signing_package, verifying_key));

    // Compute relation values to verify this signature share.
    let result = signature_share.verify(
        identifier,
        &r_share,
        &verifying_share,
        lambda_i,
        &challenge,
    ).is_ok();

	utils::to_pydict(py, &result)
}

#[pyfunction]
pub fn aggregate(py: Python, signing_package: &PyAny, signature_shares: &PyAny, pubkey_package: &PyAny) -> PyResult<PyObject> {
	let signing_package: frost_evm::SigningPackage = utils::from_pydict(signing_package)?;
	let signature_shares: HashMap<Identifier, round2::SignatureShare> = utils::from_pydict(signature_shares)?;
	let pubkey_package: keys::PublicKeyPackage = utils::from_pydict(pubkey_package)?;
	let group_signature: frost_evm::Signature = RET_ERR!(
        frost_evm::aggregate(&signing_package, &signature_shares, &pubkey_package)
    );
    let hex_str = group_signature.to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b)) // Format each byte as two hex digits
        .collect::<Vec<String>>()
        .join("");	utils::to_pydict(py, &hex_str)
}

#[pyfunction]
pub fn verify_group_signature(py: Python, signature: &str, msg: &PyBytes, pubkey_package: &PyAny) -> PyResult<PyObject> {
	let sign_bytes = RET_ERR!(hex::decode(signature));
    let mut fixed_size = [0u8; 64];
    fixed_size.copy_from_slice(sign_bytes.as_slice());
	let group_signature = RET_ERR!(frost_evm::Signature::from_bytes(fixed_size));
	let pubkey_package: frost_evm::keys::PublicKeyPackage = utils::from_pydict(pubkey_package)?;
    let verifying_key = frost_evm::schnorr::VerifyingKey::new(pubkey_package.verifying_key().to_element());
	let verified: bool = verifying_key
		.verify(&msg.as_bytes(), &group_signature)
		.is_ok();
	utils::to_pydict(py, &verified)
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(num_to_id, m)?)?;
    m.add_function(wrap_pyfunction!(keypair_new, m)?)?;
    m.add_function(wrap_pyfunction!(get_pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(single_sign, m)?)?;
    m.add_function(wrap_pyfunction!(single_verify, m)?)?;
    m.add_function(wrap_pyfunction!(keys_split, m)?)?;
    m.add_function(wrap_pyfunction!(keys_generate_with_dealer, m)?)?;
    m.add_function(wrap_pyfunction!(dkg_part1, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof_of_knowledge, m)?)?;
    m.add_function(wrap_pyfunction!(dkg_part2, m)?)?;
    m.add_function(wrap_pyfunction!(dkg_verify_secret_share, m)?)?;
    m.add_function(wrap_pyfunction!(dkg_part3, m)?)?;
    m.add_function(wrap_pyfunction!(keys_reconstruct, m)?)?;
    m.add_function(wrap_pyfunction!(key_package_from, m)?)?;
    m.add_function(wrap_pyfunction!(round1_commit, m)?)?;
    m.add_function(wrap_pyfunction!(signing_package_new, m)?)?;
    m.add_function(wrap_pyfunction!(round2_sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify_share, m)?)?;
    m.add_function(wrap_pyfunction!(aggregate, m)?)?;
    m.add_function(wrap_pyfunction!(pubkey_tweak, m)?)?;
    m.add_function(wrap_pyfunction!(pubkey_package_tweak, m)?)?;
    m.add_function(wrap_pyfunction!(key_package_tweak, m)?)?;
    m.add_function(wrap_pyfunction!(verify_group_signature, m)?)?;
    Ok(())
}
