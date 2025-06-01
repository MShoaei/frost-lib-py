use pyo3::prelude::*;

pub mod common;

pub mod ed25519;
pub mod secp256k1;
pub mod secp256k1_tr;
pub mod secp256k1_evm;

#[pymodule]
fn frost_core(py: Python, m: &PyModule) -> PyResult<()> {
    let secp_mod = PyModule::new(py, "ed25519")?;
    ed25519::register(py, secp_mod)?;
    m.add_submodule(secp_mod)?;

    let secp_mod = PyModule::new(py, "secp256k1")?;
    secp256k1::register(py, secp_mod)?;
    m.add_submodule(secp_mod)?;

    let tr_mod = PyModule::new(py, "secp256k1_tr")?;
    secp256k1_tr::register(py, tr_mod)?;
    m.add_submodule(tr_mod)?;

    let evm_mod = PyModule::new(py, "secp256k1_evm")?;
    secp256k1_evm::register(py, evm_mod)?;
    m.add_submodule(evm_mod)?;

    Ok(())
}
