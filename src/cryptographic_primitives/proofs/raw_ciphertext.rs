use crate::BigInt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawCiphertext {
    pub c: BigInt,
}

impl RawCiphertext {
    pub fn new(c: BigInt) -> Self {
        RawCiphertext { c }
    }

    pub fn inner(&self) -> &BigInt {
        &self.c
    }
}
