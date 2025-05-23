use frost_core::{Ciphersuite, Identifier, Error};
use serde::{
	Serialize, 
	de::DeserializeOwned
};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{to_value, Value};
use pyo3::{PyAny, PyErr};
use pyo3::exceptions::PyValueError;
use super::structs::SerializableScalar;


pub fn from_json_value<T: DeserializeOwned>(value: Value) -> Result<T, Box<dyn std::error::Error>> {
    let type_name = std::any::type_name::<T>();
    let result = serde_json::from_value(value)
        .map_err(|e| format!("{}: Deserialization from JSON value failed: {}", type_name, e))?;
    Ok(result)
}

pub fn b2id<C: Ciphersuite>(id: Vec<u8>) -> Result<Identifier<C>, Error<C>> {
    // Check if the length is within valid bounds
    if id.len() < 1 || id.len() > 32 {
        return Err(Error::MalformedIdentifier); // Assuming an appropriate error variant exists
    }

    // Create a fixed-size array with 32 bytes, initialized to 0
    let mut fixed_size_data: [u8; 32] = [0x00; 32];
    
    // Copy the contents of the bytes into the fixed-size array
    fixed_size_data[..id.len()].copy_from_slice(&id);

    // Create an Identifier from the fixed-size byte array
    Identifier::deserialize(&fixed_size_data).map_err(|_| Error::MalformedIdentifier)
}

pub fn json_value_to_py(py: Python, value: Value) -> PyResult<PyObject> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py(py))
            } else {
                Err(pyo3::exceptions::PyValueError::new_err("Invalid number"))
            }
        }
        Value::String(s) => Ok(s.into_py(py)),
        Value::Array(arr) => {
            let list: Vec<_> = arr
                .into_iter()
                .map(|v| json_value_to_py(py, v))
                .collect::<Result<_, _>>()?;
            Ok(PyList::new(py, list).into_py(py))
        }
        Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (k, v) in obj {
                dict.set_item(k, json_value_to_py(py, v)?)?;
            }
            Ok(dict.into_py(py))
        }
    }
}

pub fn py_to_json_value(obj: &PyAny) -> PyResult<Value> {
    if obj.is_none() {
        Ok(Value::Null)
    } else if let Ok(val) = obj.downcast::<PyBool>() {
        Ok(Value::Bool(val.is_true()))
    } else if let Ok(val) = obj.downcast::<PyInt>() {
        // Handles large ints as well
        // Try extracting as i64, fall back to u64 and convert to Number
        if let Ok(i) = val.extract::<i64>() {
            Ok(Value::Number(i.into()))
        } else if let Ok(u) = val.extract::<u64>() {
            Ok(Value::Number(u.into()))
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Integer too large to convert to JSON number",
            ))
        }
    } else if let Ok(val) = obj.downcast::<PyFloat>() {
        Ok(serde_json::Number::from_f64(val.value())
            .map(Value::Number)
            .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("Invalid float"))?)
    } else if let Ok(val) = obj.downcast::<PyString>() {
        Ok(Value::String(val.to_string()))
    } else if let Ok(seq) = obj.downcast::<PyList>() {
        let mut vec = Vec::with_capacity(seq.len());
        for item in seq.iter() {
            vec.push(py_to_json_value(item)?);
        }
        Ok(Value::Array(vec))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            let key_str = key.str()?.to_string();
            map.insert(key_str, py_to_json_value(value)?);
        }
        Ok(Value::Object(map))
    } else {
        Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(format!(
            "Unsupported Python type: {:?}",
            obj.get_type()
        )))
    }
}

pub fn to_pydict<T: Serialize>(py: Python<'_>, obj: &T) -> PyResult<PyObject> {
    let json_val = to_value(obj)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    json_value_to_py(py, json_val)
}

pub fn from_pydict<T: DeserializeOwned>(py_obj: &PyAny) -> Result<T, PyErr> {
    let json_val: Value = py_to_json_value(py_obj)?;
    from_json_value(json_val).map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
}

pub fn bytes_to_scalar(bytes: &[u8]) -> Result<SerializableScalar, Box<dyn std::error::Error>> {
    if bytes.len() > 32 {
        return Err("Expected at most 32 bytes".into());
    }

    // Left-pad (zero pad at the start) to ensure 32-byte big-endian scalar
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    padded.reverse();

    SerializableScalar::deserialize(&padded).map_err(|e| e.into())
}
