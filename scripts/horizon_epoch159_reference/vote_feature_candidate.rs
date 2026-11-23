use solana_sdk::{
    account::Account,
    feature_set::{check_init_vote_data, FeatureSet},
    instruction::InstructionError,
    keyed_account::KeyedAccount,
    pubkey::Pubkey,
    sysvar::clock::Clock,
};
use solana_vote_program::{
    id,
    vote_state::{initialize_account, VoteInit, VoteState},
};
use std::collections::HashSet;

#[test]
fn historical_vote_init_before_and_after_activation() {
    let feature = check_init_vote_data::id();
    assert!(FeatureSet::default().inactive.contains(&feature));
    assert!(!FeatureSet::default().is_active(&feature));

    let node = Pubkey::new_unique();
    let vote_account = Pubkey::new_unique();
    let signers: HashSet<_> = vec![node].into_iter().collect();
    let init = VoteInit {
        node_pubkey: node,
        authorized_voter: vote_account,
        authorized_withdrawer: vote_account,
        commission: 0,
    };
    for &(active, exact_size) in &[(false, false), (false, true), (true, true), (true, false)] {
        let size = VoteState::size_of() * if exact_size { 1 } else { 2 };
        let data = Account::new_ref(100, size, &id());
        let keyed = KeyedAccount::new(&vote_account, false, &data);
        assert!(VoteState::is_uninitialized_no_deser(&data.borrow().data));
        let result = initialize_account(&keyed, &init, &signers, &Clock::default(), active);
        if active && !exact_size {
            assert_eq!(result, Err(InstructionError::InvalidAccountData));
        } else {
            assert_eq!(result, Ok(()));
            if exact_size {
                assert!(!VoteState::is_uninitialized_no_deser(&data.borrow().data));
            }
        }
    }
}
