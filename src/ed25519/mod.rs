use pyo3::prelude::*;

#[pyfunction]
fn example_method() -> String {
    "Hello from ed25519!".to_string()
}

pub fn register(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(example_method, m)?)?;
    Ok(())
}
