use pyo3::{
    prelude::*,
    types::PyBytes
};
use frost_core::Group;
use frost_secp256k1::{
    Secp256K1Sha256,
	self as frost, keys:: {
		self, dkg, KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifiableSecretSharingCommitment, VerifyingShare
	}, round1, round2::{self, SignatureShare}, Identifier, Signature, SigningKey, SigningPackage, VerifyingKey
};
use rand::thread_rng;
use structs::{SerializableR1SecretPackage, SerializableR2SecretPackage, SerializableScalar, SerializableKeyPair};
use std::collections::BTreeMap;
use hex;
use serde::{
	Serialize, 
	Deserialize,
};

mod structs;
mod utils;

macro_rules! RET_ERR {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                    format!(r#"{{"error": "{}"}}"#, err),
                ));
            }
        }
    };
}

#[pyfunction]
fn num_to_id(py: Python, num: u64) -> PyResult<PyObject> {
	let bytes: Vec<u8> = num.to_be_bytes().to_vec(); 
	let mut padded_vec = vec![0u8; 32];
	padded_vec[24..].copy_from_slice(&bytes);
	let identifier: Identifier = RET_ERR!(Identifier::deserialize(&padded_vec));
    
    utils::to_pydict(py, &identifier)
}

#[pyfunction]
fn keypair_new(py: Python) -> PyResult<PyObject> {
	let mut rng = thread_rng();
    let signing_key = SigningKey::new(&mut rng);
    let verifying_key = signing_key.into();

    let result = SerializableKeyPair {
        signing_key: frost_core::serialization::SerializableScalar(signing_key.to_scalar()),
        verifying_key: verifying_key
    };

    utils::to_pydict(py, &result)
}

#[pyfunction]
fn get_pubkey(py: Python, secret_hex: &PyAny) -> PyResult<PyObject> {
    let scalar:SerializableScalar = utils::from_pydict(secret_hex)?;
    let secret = SigningKey::from_scalar(scalar.0)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let result = VerifyingKey::from(&secret);
    utils::to_pydict(py, &result)
}

#[pyfunction]
fn single_sign(py: Python, secret_hex: &PyAny, msg: &PyBytes) -> PyResult<PyObject> {
    let scalar:SerializableScalar = utils::from_pydict(secret_hex)?;
    let secret = SigningKey::from_scalar(scalar.0)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    // Get message bytes
    let message = msg.as_bytes();

    // Sign
    let rng = thread_rng();
    let signature = secret.sign(rng, message);

    utils::to_pydict(py, &signature)
}

#[pyfunction]
fn single_verify(py: Python, signature: &PyAny, msg: &PyBytes, pubkey: &PyAny) -> PyResult<PyObject> {
	let signature: frost_core::Signature<Secp256K1Sha256> = utils::from_pydict(signature)?;

	let pubkey: VerifyingKey = utils::from_pydict(pubkey)?;
    
    let verified = match pubkey.verify(msg.as_bytes(), &signature) {
        Ok(()) => true,
        Err(_e) => false   
    };

    utils::to_pydict(py, &verified)
}

#[pyfunction]
fn keys_split(py: Python, secret: &PyAny, max_signers: u16, min_signers: u16) -> PyResult<PyObject> {
	let scalar: SerializableScalar = utils::from_pydict(secret)?;
	let secret: SigningKey = RET_ERR!(SigningKey::from_scalar(scalar.0));
	let mut rng = thread_rng();
	let (shares, pubkey_package) = RET_ERR!(frost::keys::split(
		&secret,
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		&mut rng,
	));
	let result = DealerKeysResult { shares, pubkey_package };

	utils::to_pydict(py, &result)
}

#[derive(Serialize, Deserialize)]
pub struct DealerKeysResult {
	shares: BTreeMap<Identifier, SecretShare>,
	pubkey_package: PublicKeyPackage,
}

#[pyfunction]
fn keys_generate_with_dealer(py: Python, max_signers: u16, min_signers: u16) -> PyResult<PyObject> {
	let rng = thread_rng();
	let (shares, pubkey_package) = RET_ERR!(frost::keys::generate_with_dealer(
		max_signers,
		min_signers,
		frost::keys::IdentifierList::Default,
		rng,
	));
	let result = DealerKeysResult { shares, pubkey_package };
	utils::to_pydict(py, &result)
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart1Result{
	secret_package: structs::SerializableR1SecretPackage,
	package: keys::dkg::round1::Package
}

#[pyfunction]
fn dkg_part1(py: Python, id_hex: String, max_signers: u16, min_signers: u16) -> PyResult<PyObject> {
	let id_bytes: Vec<u8> = RET_ERR!(hex::decode(id_hex));
	let identifier: Identifier = RET_ERR!(utils::b2id(id_bytes));
	
	let mut rng = thread_rng();
    let (secret_package, package) = RET_ERR!(frost::keys::dkg::part1(
        identifier,
        max_signers,
        min_signers,
        &mut rng,
    ));

	let result = DkgPart1Result { 
        secret_package: secret_package.into(), 
        package
    };

	utils::to_pydict(py, &result)
}

/// every proof of knowledge received from dkg_part1 must be validate with this method.
/// dkg_part2 validate this proofs it self, and throw an error if faild.
/// to find out which party behaves malicious, proof_of_knowledge of each partners must be check after dkg_part2 failure.
#[pyfunction]
fn verify_proof_of_knowledge(py: Python, id: &PyAny, commitments: &PyAny, signature: &PyAny) -> PyResult<PyObject> {
	let identifier: Identifier = utils::from_pydict(id)?;
	let vss:VerifiableSecretSharingCommitment = utils::from_pydict(commitments)?;
	let signature: Signature = utils::from_pydict(signature)?;
	let result = frost_core::keys::dkg::verify_proof_of_knowledge(
		identifier, 
		&vss, 
		&signature);
    
	utils::to_pydict(py, &result.is_ok())
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart2Result{
	secret_package: SerializableR2SecretPackage,
	packages: BTreeMap<Identifier, keys::dkg::round2::Package>,
}

#[pyfunction]
fn dkg_part2(py: Python, r1_skrt_pkg: &PyAny, r1_pkg: &PyAny) -> PyResult<PyObject> {
	let round1_secret_package: SerializableR1SecretPackage = utils::from_pydict(r1_skrt_pkg)?;
	let round1_packages: BTreeMap<Identifier, dkg::round1::Package> = utils::from_pydict(r1_pkg)?;
	let (secret_package, packages) = RET_ERR!(frost::keys::dkg::part2(
		round1_secret_package.into(), 
		&round1_packages
	));

	let result = DkgPart2Result {
		secret_package: secret_package.into(), 
		packages
	};

	utils::to_pydict(py, &result)
}

/// This method is called by the receiver of a secret share during the Distributed Key Generation (DKG) protocol.
/// 
/// Each secret share received from the `dkg_part2` process must be validated using this method before proceeding to `dkg_part3`.
/// 
/// If `dkg_part3` fails, it automatically validates the received shares and throws an error if validation fails.
/// To identify which party acted maliciously, all received shares from each partner should be re-validated after a `dkg_part3` failure.
/// 
/// ### Inputs:
/// - `id`: A pointer to the unique identifier of the participant receiving the share.
/// - `share_buff`: A buffer containing received secret share.
/// - `commitment_buff`: A buffer contains the received commitment associated with the share.
/// 
/// ### Output:
/// - Returns a pointer to buffer containing boolean json str
#[pyfunction]
fn dkg_verify_secret_share(py: Python, id: &PyAny, share: &PyAny, commitment: &PyAny) -> PyResult<PyObject> {
	let identifier: Identifier = utils::from_pydict(id)?;
	let signing_share: SigningShare = utils::from_pydict(share)?;
	let commitment: VerifiableSecretSharingCommitment = utils::from_pydict(commitment)?;

	let secret_share = SecretShare::new(identifier, signing_share, commitment);

	let verified = secret_share.verify();
	utils::to_pydict(py, &verified.is_ok())
}

#[derive(Serialize, Deserialize)]
pub struct DkgPart3Result{
	key_package: keys::KeyPackage,
	pubkey_package: keys::PublicKeyPackage,
}

#[pyfunction]
fn dkg_part3(py: Python, r2_sec_pkg: &PyAny, r1_pkgs: &PyAny, r2_pkgs: &PyAny) -> PyResult<PyObject> {
	let round2_secret_package: SerializableR2SecretPackage = utils::from_pydict(r2_sec_pkg)?;
	let round1_packages: BTreeMap<Identifier, dkg::round1::Package> = utils::from_pydict(r1_pkgs)?;
	let round2_packages: BTreeMap<Identifier, dkg::round2::Package> = utils::from_pydict(r2_pkgs)?;
	let (key_package, pubkey_package) = RET_ERR!(keys::dkg::part3(
        &round2_secret_package.into(),
        &round1_packages,
        &round2_packages,
    ));

	let result = DkgPart3Result {
		key_package, 
		pubkey_package
	};

	utils::to_pydict(py, &result)
}

#[pyfunction]
fn keys_reconstruct(py: Python, secret_shares: &PyAny, min_signers: u16) -> PyResult<PyObject> {
    let secret_shares: Vec<KeyPackage> = utils::from_pydict(secret_shares)?; 
    
    if secret_shares.len() != min_signers as usize {
        RET_ERR!(Err(format!(
            "Number of secret shares ({}) must equal min_signers ({})",
            secret_shares.len(),
            min_signers
        )));
    }

    let signing_key: SigningKey = RET_ERR!(frost::keys::reconstruct(&secret_shares));

    let result:SerializableScalar = frost_core::serialization::SerializableScalar(signing_key.to_scalar());
    utils::to_pydict(py, &result)
}

#[pyfunction]
fn key_package_from(py: Python, secret_share: &PyAny) -> PyResult<PyObject> {
	let share: SecretShare = utils::from_pydict(secret_share)?;
	let key_package = RET_ERR!(frost::keys::KeyPackage::try_from(share));
	utils::to_pydict(py, &key_package)
}

#[derive(Serialize, Deserialize)]
pub struct Round1CommitResult {
	nonces: frost::round1::SigningNonces,
	commitments: frost::round1::SigningCommitments,
}

#[pyfunction]
fn round1_commit(py: Python, secret: &PyAny) -> PyResult<PyObject> {
	let secret: SigningShare = utils::from_pydict(secret)?;
	let mut rng = thread_rng();
	let (nonces, commitments) = frost::round1::commit(&secret, &mut rng);
	let result = Round1CommitResult {nonces, commitments};
	utils::to_pydict(py, &result)
}

#[pyfunction]
fn signing_package_new(py: Python, signing_commitments: &PyAny, msg: &PyBytes) -> PyResult<PyObject> {
	let signing_commitments: BTreeMap<Identifier, round1::SigningCommitments> = 
        utils::from_pydict(signing_commitments)?;
	let message = msg.as_bytes();
	let signing_package = frost::SigningPackage::new(signing_commitments, &message);
	utils::to_pydict(py, &signing_package)
}

#[pyfunction]
fn round2_sign(py: Python, signing_package: &PyAny, signer_nonces: &PyAny, key_package: &PyAny) -> PyResult<PyObject> {
	let signing_package: SigningPackage = utils::from_pydict(signing_package)?;
	let signer_nonces: round1::SigningNonces = utils::from_pydict(signer_nonces)?;
	let key_package: keys::KeyPackage = utils::from_pydict(key_package)?;
	let signature_share: round2::SignatureShare = RET_ERR!(frost::round2::sign(&signing_package, &signer_nonces, &key_package));
	utils::to_pydict(py, &signature_share)
}

#[pyfunction]
fn verify_share(
    py: Python,
	identifier: &PyAny,
	verifying_share: &PyAny, 
	signature_share: &PyAny, 
	signing_package: &PyAny, 
	verifying_key: &PyAny
) -> PyResult<PyObject> {
	let identifier: Identifier = utils::from_pydict(identifier)?;
	let verifying_share: VerifyingShare = utils::from_pydict(verifying_share)?;
	let signature_share: SignatureShare = utils::from_pydict(signature_share)?;
	let signing_package: SigningPackage = utils::from_pydict(signing_package)?;
	let verifying_key: VerifyingKey = utils::from_pydict(verifying_key)?;

	let result = frost_core::verify_signature_share(
		identifier, 
		&verifying_share, 
		&signature_share, 
		&signing_package, 
		&verifying_key
	);
	utils::to_pydict(py, &result.is_ok())
}

#[pyfunction]
fn aggregate(py: Python, signing_package: &PyAny, signature_shares: &PyAny, pubkey_package: &PyAny) -> PyResult<PyObject> {
	let signing_package: frost::SigningPackage = utils::from_pydict(signing_package)?;
	let signature_shares: BTreeMap<Identifier, round2::SignatureShare> = utils::from_pydict(signature_shares)?;
	let pubkey_package: keys::PublicKeyPackage = utils::from_pydict(pubkey_package)?;
	let group_signature: frost::Signature = RET_ERR!(frost::aggregate(&signing_package, &signature_shares, &pubkey_package));
	utils::to_pydict(py, &group_signature)
}

#[pyfunction]
fn pubkey_tweak(py: Python, pubkey: &PyAny, tweak_by: &PyBytes) -> PyResult<PyObject> {
	let pubkey: VerifyingKey = utils::from_pydict(pubkey)?;

    // let t: SerializableScalar = utils::from_pydict(tweak_by)?;
    let t: SerializableScalar = RET_ERR!(utils::bytes_to_scalar(tweak_by.as_bytes()));
    
    let t_pub = frost::Secp256K1Group::generator() * t.0;

    let pubkey_tweaked =
        VerifyingKey::new(pubkey.to_element() + t_pub);

    utils::to_pydict(py, &pubkey_tweaked)
}

#[pyfunction]
fn pubkey_package_tweak(py: Python, pubkey_package: &PyAny, tweak_by: &PyBytes) -> PyResult<PyObject> {
	let pubkey_package: keys::PublicKeyPackage = utils::from_pydict(pubkey_package)?;
    let t: SerializableScalar = RET_ERR!(utils::bytes_to_scalar(tweak_by.as_bytes()));

    let t_pub = frost::Secp256K1Group::generator() * t.0;

    let verifying_key =
        VerifyingKey::new(pubkey_package.verifying_key().to_element() + t_pub);
    let verifying_shares: BTreeMap<_, _> = pubkey_package
        .verifying_shares()
        .iter()
        .map(|(i, vs)| {
            let vs = VerifyingShare::new(vs.to_element() + t_pub);
            (*i, vs)
        })
        .collect();

	let pubkey_package_tweaked = PublicKeyPackage::new(verifying_shares, verifying_key);
	utils::to_pydict(py, &pubkey_package_tweaked)
}

#[pyfunction]
fn key_package_tweak(py: Python, key_package: &PyAny, tweak_by: &PyBytes) -> PyResult<PyObject> {
	let key_package: keys::KeyPackage = utils::from_pydict(key_package)?;
    let t: SerializableScalar = RET_ERR!(utils::bytes_to_scalar(tweak_by.as_bytes()));

    let t_pub = frost::Secp256K1Group::generator() * t.0;

    let verifying_key = VerifyingKey::new(key_package.verifying_key().to_element() + t_pub);
    let signing_share = SigningShare::new(key_package.signing_share().to_scalar() + t.0);
    let verifying_share =
        VerifyingShare::new(key_package.verifying_share().to_element() + t_pub); 

    let key_package_tweaked = KeyPackage::new(
        *key_package.identifier(), 
        signing_share, 
        verifying_share, 
        verifying_key, 
        *key_package.min_signers()
    );

	utils::to_pydict(py, &key_package_tweaked)
}

#[pyfunction]
fn verify_group_signature(py: Python, signature: &PyAny, msg: &PyBytes, pubkey_package: &PyAny) -> PyResult<PyObject> {
	let group_signature:frost::Signature = utils::from_pydict(signature)?;
	let pubkey_package: PublicKeyPackage = utils::from_pydict(pubkey_package)?;
	let verified: bool = pubkey_package
		.verifying_key()
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