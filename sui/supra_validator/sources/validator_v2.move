module supra_validator::validator_v2 {

    use std::vector;
    use sui::bls12381;
    use sui::clock::{Self, Clock};
    use sui::event::emit;
    use sui::transfer;
    use sui::tx_context::TxContext;
    use sui::object::{Self, UID};
    use sui::vec_map::{Self, VecMap};
    use supra_validator::validator::OwnerCap;

    // Track the current version of the module
    const VERSION: u64 = 1;

    /// Committee id -> public key mapping is missing from the map
    const ECOMMITTEE_KEY_DOES_NOT_EXIST: u64 = 1;
    /// The committee public key is identical to the one already stored
    const ECOMMITTEE_PUBKEY_IS_SAME: u64 = 2;
    /// Invalid Public key lnput
    const EINVALID_PUBLIC_KEY: u64 = 3;
    /// Calling functions from the wrong package version
    const EWRONG_DKG_STATE_VERSION: u64 = 4;

    /// define public key length
    const PUBLIC_KEY_LENGTH: u64 = 96;

    /// Manage DKG pubkey key to verify BLS signature
    struct DkgState has key, store {
        id: UID,
        version: u64,
        // map from committee-id to the committee public key
        com_to_pub_key: VecMap<u64, vector<u8>>,
    }

    /// Store Public Key event
    struct StorePublicKeyEvent has drop, copy { committee_id: u64, public_key: vector<u8>, timestamp: u64 }

    /// Remove Public key event
    struct RemovePublicKeyEvent has drop, copy { committee_id: u64, public_key: vector<u8>, timestamp: u64 }

    /// Internal - DkgState implementaion functions
    fun create_dkg_state(ctx: &mut TxContext) {
        let dkg_state = DkgState { id: object::new(ctx), version: VERSION, com_to_pub_key: vec_map::empty() };
        transfer::share_object(dkg_state)
    }

    /// Its Initial function which will be executed automatically while deployed packages
    fun init(ctx: &mut TxContext) {
        create_dkg_state(ctx);
    }

    /// Only Owner can perform this action
    /// This function add/updates the public key associated with the given `committee_id` in the `DkgState`.
    public entry fun add_committee_public_key(
        _: &mut OwnerCap,
        dkg_state: &mut DkgState,
        clock: &Clock,
        committee_id: u64,
        public_key: vector<u8>,
        _ctx: &mut TxContext
    ) {
        dkg_state_version_check(dkg_state);
        assert!(vector::length(&public_key) == PUBLIC_KEY_LENGTH, EINVALID_PUBLIC_KEY);
        if (vec_map::contains(&dkg_state.com_to_pub_key, &committee_id)) {
            let committee_public_key = vec_map::get_mut(&mut dkg_state.com_to_pub_key, &committee_id);
            assert!(public_key != *committee_public_key, ECOMMITTEE_PUBKEY_IS_SAME);
            *committee_public_key = public_key;
        } else {
            vec_map::insert(&mut dkg_state.com_to_pub_key, committee_id, public_key);
        };
        emit(StorePublicKeyEvent { committee_id, public_key, timestamp: clock::timestamp_ms(clock) });
    }

    /// Only Owner can perform this action
    /// This function remove the public key associated with the given `committee_id` from the `DkgState`.
    public entry fun remove_committee_public_key(
        _: &mut OwnerCap,
        dkg_state: &mut DkgState,
        clock: &Clock,
        committee_id: u64,
        _ctx: &mut TxContext
    ) {
        dkg_state_version_check(dkg_state);
        ensure_committee_public_key_exist(dkg_state, committee_id);
        let (_, public_key) = vec_map::remove(&mut dkg_state.com_to_pub_key, &committee_id);
        emit(RemovePublicKeyEvent { committee_id, public_key, timestamp: clock::timestamp_ms(clock) });
    }

    /// Committee signature verification
    public fun committee_sign_verification(
        dkg_state: &DkgState,
        committee_id: u64,
        root: vector<u8>,
        sign: vector<u8>
    ): bool {
        let public_key = get_committee_public_key(dkg_state, committee_id);
        bls12381::bls12381_min_sig_verify(&sign, &public_key, &root)
    }

    /// Internal function - ensure that committee public key is exist in the DkgState
    fun ensure_committee_public_key_exist(dkg_state: &DkgState, committee_id: u64) {
        assert!(vec_map::contains(&dkg_state.com_to_pub_key, &committee_id), ECOMMITTEE_KEY_DOES_NOT_EXIST);
    }

    /// Get length of the committee public key
    public fun get_committee_public_key_length(dkg_state: &DkgState): u64 {
        vec_map::size(&dkg_state.com_to_pub_key)
    }

    /// Get committee public key from committee index
    public fun get_committee_public_key(dkg_state: &DkgState, committee_id: u64): vector<u8> {
        dkg_state_version_check(dkg_state);
        ensure_committee_public_key_exist(dkg_state, committee_id);
        *vec_map::get(&dkg_state.com_to_pub_key, &committee_id)
    }

    /// we are upgrading our package, so in that case, the 'init' function won't be called automatically; we need to do it with migrate call
    entry fun migrate(_: &mut OwnerCap, ctx: &mut TxContext) {
        create_dkg_state(ctx);
    }

    public fun dkg_state_version_check(dkg_state: &DkgState) {
        assert!(dkg_state.version == VERSION, EWRONG_DKG_STATE_VERSION);
    }

    #[test_only]
    public fun init_for_test(ctx: &mut TxContext) {
        supra_validator::validator::create_dkg_state_for_test(ctx);
        create_dkg_state(ctx)
    }

    #[test]
    fun test_add_remove_committe_public_key() {
        use sui::test_scenario;
        use std::vector;
        let admin = @supra_validator;

        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;
        test_scenario::next_tx(scenario, admin);
        {
            init_for_test(test_scenario::ctx(scenario));
        };

        test_scenario::next_tx(scenario, admin);
        {
            let owner_cap = test_scenario::take_from_sender<OwnerCap>(scenario);
            let dkg_state = test_scenario::take_shared<DkgState>(scenario);
            let clock = sui::clock::create_for_testing(test_scenario::ctx(scenario));

            let committee_ids = vector[1, 2];
            let public_keys = vector[
                vector[175, 109, 230, 142, 211, 121, 66, 220, 116, 189, 244, 44, 225, 195, 196, 80, 12, 17, 223, 228, 183, 180, 6, 209, 10, 247, 80, 38, 110, 236, 158, 17, 168, 166, 61, 86, 7, 4, 71, 23, 59, 217, 168, 47, 99, 186, 48, 18, 24, 53, 127, 133, 188, 27, 114, 84, 142, 45, 94, 1, 155, 21, 108, 211, 134, 231, 8, 22, 192, 93, 216, 245, 229, 105, 212, 214, 56, 113, 146, 127, 244, 204, 192, 82, 139, 126, 214, 62, 47, 176, 125, 207, 14, 217, 92, 62],
                vector[153, 60, 89, 255, 174, 79, 248, 128, 29, 140, 140, 17, 1, 219, 149, 103, 163, 28, 128, 139, 24, 54, 161, 157, 33, 35, 233, 185, 237, 246, 220, 210, 30, 128, 135, 73, 42, 159, 182, 8, 162, 192, 26, 206, 146, 216, 159, 186, 23, 42, 23, 160, 153, 106, 37, 200, 225, 232, 152, 63, 107, 188, 209, 187, 2, 230, 98, 5, 127, 143, 62, 245, 243, 134, 255, 204, 249, 149, 235, 201, 19, 218, 187, 134, 55, 90, 44, 109, 57, 94, 175, 214, 169, 209, 82, 151]
            ];
            add_committee_public_key(
                &mut owner_cap,
                &mut dkg_state,
                &clock,
                *vector::borrow(&committee_ids, 0),
                *vector::borrow(&public_keys, 0),
                test_scenario::ctx(scenario)
            );
            add_committee_public_key(
                &mut owner_cap,
                &mut dkg_state,
                &clock,
                *vector::borrow(&committee_ids, 1),
                *vector::borrow(&public_keys, 1),
                test_scenario::ctx(scenario)
            );

            assert!(get_committee_public_key_length(&dkg_state) == vector::length(&committee_ids), 1);
            while (!vector::is_empty(&committee_ids)) {
                let committee_id = vector::pop_back(&mut committee_ids);
                assert!(get_committee_public_key(&dkg_state, committee_id) == vector::pop_back(&mut public_keys), 2);
            };

            test_scenario::return_to_sender(scenario, owner_cap);
            test_scenario::return_shared(dkg_state);
            sui::clock::share_for_testing(clock);
        };

        test_scenario::next_tx(scenario, admin);
        {
            let owner_cap = test_scenario::take_from_sender<OwnerCap>(scenario);
            let dkg_state = test_scenario::take_shared<DkgState>(scenario);
            let clock = sui::clock::create_for_testing(test_scenario::ctx(scenario));

            remove_committee_public_key(&mut owner_cap, &mut dkg_state, &clock, 1, test_scenario::ctx(scenario));
            remove_committee_public_key(&mut owner_cap, &mut dkg_state, &clock, 2, test_scenario::ctx(scenario));

            assert!(get_committee_public_key_length(&dkg_state) == 0, 3);

            test_scenario::return_to_sender(scenario, owner_cap);
            test_scenario::return_shared(dkg_state);
            sui::clock::share_for_testing(clock);
        };

        test_scenario::end(scenario_val);
    }
}
