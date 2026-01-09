#![no_std]

use risc0_interface::{
    Receipt, ReceiptClaim, RiscZeroVerifierClient, RiscZeroVerifierInterface, VerifierError,
};
use soroban_sdk::{Address, Bytes, BytesN, Env, contract, contractimpl, contracttype};

#[cfg(test)]
mod test;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Administrator address with permissions to change the router
    Admin,
    Verifier(BytesN<4>),
}

#[contracttype]
enum VerifierEntry {
    Active(Address),
    Tombstone,
}

#[contract]
pub struct RiscZeroVerifierRouter;

// This is a sample contract. Replace this placeholder with your own contract
// logic. A corresponding test example is available in `test.rs`.
//
// For comprehensive examples, visit <https://github.com/stellar/soroban-examples>.
// The repository includes use cases for the Stellar ecosystem, such as data
// storage on the blockchain, token swaps, liquidity pools, and more.
//
// Refer to the official documentation:
// <https://developers.stellar.org/docs/build/smart-contracts/overview>.
#[contractimpl]
impl RiscZeroVerifierRouter {
    pub fn __constructor(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn add_verifier(
        env: Env,
        selector: BytesN<4>,
        verifier: Address,
    ) -> Result<(), VerifierError> {
        require_admin(&env);

        let key = DataKey::Verifier(selector);
        let verifier_address: Option<VerifierEntry> = env.storage().persistent().get(&key);

        if let Some(entry) = verifier_address {
            match entry {
                VerifierEntry::Tombstone => return Err(VerifierError::SelectorRemoved),
                VerifierEntry::Active(_) => return Err(VerifierError::SelectorInUse),
            }
        }

        env.storage()
            .persistent()
            .set(&key, &VerifierEntry::Active(verifier));

        Ok(())
    }

    fn get_verifier(env: &Env, selector: &BytesN<4>) -> Result<Address, VerifierError> {
        let key = DataKey::Verifier(selector.clone());
        let verifier_address: Option<VerifierEntry> = env.storage().persistent().get(&key);

        match verifier_address {
            Some(VerifierEntry::Tombstone) => Err(VerifierError::SelectorRemoved),
            Some(VerifierEntry::Active(address)) => Ok(address),
            None => Err(VerifierError::SelectorUnknown),
        }
    }

    pub fn get_verifier_by_selector(
        env: Env,
        selector: BytesN<4>,
    ) -> Result<Address, VerifierError> {
        Self::get_verifier(&env, &selector)
    }

    pub fn get_verifier_from_seal(env: Env, seal: Bytes) -> Result<Address, VerifierError> {
        let selector = selector_from_seal(&seal);
        Self::get_verifier(&env, &selector)
    }
}

#[contractimpl]
impl RiscZeroVerifierInterface for RiscZeroVerifierRouter {
    type Proof = ();

    fn verify(env: Env, seal: Bytes, image_id: BytesN<32>, journal: BytesN<32>) {
        let claim = ReceiptClaim::new(&env, image_id, journal);
        let receipt = Receipt {
            seal,
            claim_digest: claim.digest(&env),
        };
        Self::verify_integrity(env, receipt);
    }

    fn verify_integrity(env: Env, receipt: Receipt) {
        let selector = selector_from_seal(&receipt.seal);
        let verifier = Self::get_verifier(&env, &selector).unwrap();
        let verifier = RiscZeroVerifierClient::new(&env, &verifier);
        verifier.verify_integrity(&receipt);
    }
}

fn require_admin(env: &Env) {
    let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

fn selector_from_seal(seal: &Bytes) -> BytesN<4> {
    seal.slice(0..4).try_into().unwrap()
}
