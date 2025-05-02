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
    pub h: BigInt,
}

impl QRProof {    
    pub fn prove(n: &BigInt) -> QRProof {
        // let n = pk;
        let witness: BigInt = BigInt::sample_below(&n); // witness x
        let h = BigInt::mod_pow(&witness, &BigInt::from(2), &n);
        
        let r: BigInt = BigInt::sample_below(&n);
        let a: BigInt = BigInt::mod_pow(&r, &BigInt::from(2), &n);
        
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
            &(BigInt::mod_pow(&witness, &e, &n)), 
            &r, 
            &n
        );

        QRProof {a, z, h}
    }

    pub fn verify(qr_proof: &QRProof, n: &BigInt,) -> Result<(), ProofError> {
        let &QRProof {ref a, ref z, ref h} = qr_proof;

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

    // crate::test_for_all_curves_and_hashes!(test_qr_proof);
    #[test]
    pub fn test_qr_proof() {
        let n = BigInt::sample(3072);

        let qr_proof = QRProof::prove(&n);

        match QRProof::verify(&qr_proof, &n) {
            Ok(res) => println!("Verification_qr result: {:?}", res),
            Err(error ) => panic!("Problem opening the file: {:?}", error.to_string()),
        }; 
    }
}
