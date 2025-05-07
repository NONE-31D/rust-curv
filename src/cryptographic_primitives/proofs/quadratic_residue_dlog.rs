use sha2::{Sha256, Digest};
use crate::arithmetic::traits::*;
use crate::BigInt;
use serde::{Deserialize, Serialize};
use super::ProofError;

pub const S: u32 = 128;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QRdlProof {
    pub a: BigInt,
    pub z: BigInt,
}

impl QRdlProof {    
    pub fn prove(
        n: &BigInt,
        h: &BigInt,
        witness_for_g: &BigInt,
        g: &BigInt,
    ) -> QRdlProof {
        let beta = BigInt::sample_range(&BigInt::from(1), &(BigInt::from(2).pow(S-1) * n)) * 2;
        let a = BigInt::mod_pow(&h, &beta, &n); // h^beta

        let mut hasher = Sha256::new();
        hasher.update(a.to_string().as_bytes());
        hasher.update(g.to_string().as_bytes());
        let result = hasher.finalize();
        let last_byte = result[result.len() - 1];
        let e = if last_byte & 1 == 1{ // e
            BigInt::from(1)
        } else {
            BigInt::from(0)
        };

        let z = e.clone() * witness_for_g + beta; // e * alpha + beta (integer)

        QRdlProof {a, z}
    }

    pub fn verify(
        n: &BigInt,
        h: &BigInt,
        g: &BigInt,
        qrdl_proof: &QRdlProof, 
    ) -> Result<(), ProofError> {
        let &QRdlProof {ref a, ref z} = qrdl_proof;

        let mut hasher = Sha256::default();
        hasher.update(a.to_string().as_bytes());
        hasher.update(g.to_string().as_bytes()); 
        let result = hasher.finalize();
        let last_byte = result[result.len() - 1];
        let e = if last_byte & 1 == 1{
            BigInt::from(1)
        } else {
            BigInt::from(0)
        }; //e

        let lhs = BigInt::mod_pow(&h, &z, &n);
        let rhs = BigInt::mod_mul(
            &(BigInt::mod_pow(&g, &e, &n)),
            &a,
            n,
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
    // use crate::cryptographic_primitives::proofs::quadratic_residue::QRProof;

    use super::*;

    #[test]
    pub fn test_qrdl_proof() {
        let n = BigInt::sample(3072); // pk

        let witness_for_h = BigInt::sample_below(&n); // witness x
        let h = BigInt::mod_pow(&witness_for_h, &BigInt::from(2), &n);

        let witness_for_g = BigInt::sample_below(&n); // witness alpha
        let g = BigInt::mod_pow(&h, &witness_for_g, &n);
        let qrdl_proof = QRdlProof::prove(&n, &h, &witness_for_g, &g);

        match QRdlProof::verify(&n, &h, &g, &qrdl_proof) {
            Ok(res) => println!("Verification_qrdl result: {:?}", res),
            Err(error ) => panic!("Problem opening the file: {:?}", error.to_string()),
        }; 
    }
}
