use super::*;
use soroban_sdk::Env;

#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register(RiscZeroVerifierRouter, ());
    let _client = RiscZeroVerifierRouterClient::new(&env, &contract_id);
}
