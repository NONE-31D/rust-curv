use sha2::{Sha256, Digest};
use crate::arithmetic::traits::*;
use crate::BigInt;
use serde::{Deserialize, Serialize};
use super::ProofError;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QRProof {
    pub a: BigInt,
    pub z: BigInt,
}

impl QRProof {    
    pub fn prove(
        n: &BigInt,
        witness_for_h: &BigInt,
        h: &BigInt,
    ) -> QRProof {
        let randomness: BigInt = BigInt::sample_below(&n);
        let a: BigInt = BigInt::mod_pow(&randomness, &BigInt::from(2), &n);
        
        let mut hasher = Sha256::default();
        hasher.update(a.to_string().as_bytes());
        hasher.update(h.to_string().as_bytes()); 
        let result = hasher.finalize();
        let last_byte = result[result.len() - 1];
        let e = if last_byte & 1 == 1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };
        
        let z = BigInt::mod_mul(
            &(BigInt::mod_pow(&witness_for_h, &e, &n)), 
            &randomness, 
            &n
        );

        QRProof {a, z}
    }

    pub fn verify(
        n: &BigInt,
        h: &BigInt,
        qr_proof: &QRProof,
    ) -> Result<(), ProofError> {
        let &QRProof {ref a, ref z} = qr_proof;

        let mut hasher = Sha256::default();
        hasher.update(a.to_string().as_bytes());
        hasher.update(h.to_string().as_bytes()); 
        let result = hasher.finalize();
        let last_byte = result[result.len() - 1];
        let e = if last_byte & 1 == 1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };

        let lhs = BigInt::mod_pow(&z, &BigInt::from(2), &n); // z^2
        let rhs = BigInt::mod_mul( // h^e * a 
            &(BigInt::mod_pow(&h, &e, &n)),
            &a,
            &n,
        );

        if lhs == rhs {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_qr_proof() {
        let n = BigInt::sample(3072); // pk

        let witness_for_h = BigInt::sample_below(&n); // witness x
        let h = BigInt::mod_pow(&witness_for_h, &BigInt::from(2), &n);
        let qr_proof = QRProof::prove(&n, &witness_for_h, &h);

        match QRProof::verify(&n, &h, &qr_proof) {
            Ok(res) => println!("Verification_qr result: {:?}", res),
            Err(error ) => panic!("Problem opening the file: {:?}", error.to_string()),
        }; 
    }
}
