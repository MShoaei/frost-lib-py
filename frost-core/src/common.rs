pub mod macros {
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

    pub(crate) use RET_ERR; // Make available within the crate
}
