use pairing_plus::bls12_381::Fr;
use pairing_plus::serdes::SerDes;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::pok_vc::prelude::*;
use crate::prelude::BBSError;
use crate::{
    Commitment, CommitmentBuilder, GeneratorG1, ProofChallenge, ProofNonce, SignatureMessage,
};

use ff_zeroize::Field;

/// Convenience importing module
pub mod prelude {
    pub use super::{PoKOfCommitment, PoKOfCommitmentProof};
}

/// Proof of Knowledge of a Commitment that is used by the prover
/// to construct `PoKOfCommitmentProof`.
#[derive(Debug, Clone)]
pub struct PoKOfCommitment {
    /// index i
    i: usize,
    /// Commitment c
    c: Commitment,
    /// For proving relation c == h1^m h0^r
    pok_vc: ProverCommittedG1,
    /// Secrets: m and r
    secrets: Vec<SignatureMessage>,
}

/// The actual proof that is sent from prover to verifier.
///
/// Contains the proof of knowledge of a committed value and its opening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoKOfCommitmentProof {
    /// index i
    pub i: usize,
    /// Commitment c
    pub c: Commitment,
    /// Proof of relation c == h1^m h0^r
    proof_vc: ProofG1,
}

impl PoKOfCommitment {
    /// Creates the initial proof data before a Fiat-Shamir calculation
    pub fn init(
        i: usize,
        base_m: &GeneratorG1,
        base_r: &GeneratorG1,
        m: &SignatureMessage,
        blinding_m: &ProofNonce,
    ) -> Self {
        let mut rng = thread_rng();
        let r = Fr::random(&mut rng);

        // c
        let mut builder = CommitmentBuilder::new();
        builder.add(base_m, m); // h_1^m
        builder.add(base_r, &SignatureMessage::from(r)); // h_0^r
        let c = builder.finalize(); // h_1^m * h_0^r

        // pok_vc and secrets
        let mut committing = ProverCommittingG1::new();
        let mut secrets = Vec::with_capacity(2);
        committing.commit_with(base_m, blinding_m);
        secrets.push(*m);
        committing.commit(base_r);
        secrets.push(SignatureMessage::from(r));
        let pok_vc = committing.finish();

        Self {
            i,
            c,
            pok_vc,
            secrets,
        }
    }

    /// Return byte representation of public elements so they can be used for challenge computation.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut self.i.to_be_bytes().to_vec());
        bytes.append(&mut self.c.to_bytes_uncompressed_form().to_vec());
        bytes.append(&mut self.pok_vc.to_bytes());
        bytes
    }

    /// Given the challenge value, compute the s values for Fiat-Shamir and return the actual
    /// proof to be sent to the verifier
    pub fn gen_proof(
        self,
        challenge_hash: &ProofChallenge,
    ) -> Result<PoKOfCommitmentProof, BBSError> {
        let proof_vc = self.pok_vc.gen_proof(challenge_hash, &self.secrets)?;
        Ok(PoKOfCommitmentProof {
            i: self.i,
            c: self.c,
            proof_vc,
        })
    }
}

impl PoKOfCommitmentProof {
    /// Return bytes that need to be hashed for generating challenge. Takes `self.i`,
    /// `self.c` and commitment.
    pub fn get_bytes_for_challenge(&self, base_m: &GeneratorG1, base_r: &GeneratorG1) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.append(&mut self.i.to_be_bytes().to_vec());
        bytes.append(&mut self.c.to_bytes_uncompressed_form().to_vec());
        base_m.0.serialize(&mut bytes, false).unwrap();
        base_r.0.serialize(&mut bytes, false).unwrap();
        self.proof_vc
            .commitment
            .serialize(&mut bytes, false)
            .unwrap();
        bytes
    }
}
