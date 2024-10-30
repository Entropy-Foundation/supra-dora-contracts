/// Pull Model V2: This module provides functionality for pulling and verifying price data and extracting relevant information.
/// Action:
/// User: The User can access `verify_oracle_proof` and `price_data_split` function
module SupraOracle::price_data_pull_v2 {

    use std::vector;
    use sui::transfer;
    use sui::object::{Self, UID};
    use sui::clock::Clock;
    use sui::hash::keccak256;
    use sui::tx_context::TxContext;
    use SupraOracle::SupraSValueFeed::{Self, OracleHolder, OwnerCap as HolderOwnerCap};
    use supra_utils::bcs;
    use supra_utils::enumerable_set_ring::{Self, EnnumerableSetRing};
    use supra_utils::utils;
    use supra_validator::validator_v2::{Self, DkgState};
    #[test_only]
    use sui::test_scenario;

    /// Track the current version of the module
    const VERSION: u64 = 1;
    /// Capacity of the Ring Buffer
    const RING_BUFFER_SIZE: u64 = 500;

    /// Signature verification failed
    const EINVALID_SIGNATURE: u64 = 11;
    /// Multileaf merkle proof verification failed
    const EINVALID_MERKLE_PROOF: u64 = 12;
    /// Length miss match
    const EMISSING_LENGTH: u64 = 13;

    /// Represents price data with information about the pair, price, decimal, timestamp, and stale value status
    struct PriceData has copy, drop {
        pair_index: u32,
        value: u128,
        timestamp: u64,
        decimal: u16,
        round: u64
    }

    #[allow(unused_field)]
    struct CommitteeFeedWithProof has drop {
        committee_feed: PriceData,
        // Multileaf merkle proof for the `committee_feed` (a single price pair)
        proof: vector<vector<u8>>,
    }

    #[allow(unused_field)]
    struct PriceDetailsWithCommittee has drop {
        committee_id: u64,
        // root hash of the entire merkle tree used for committee_feed and committee_id verification
        root: vector<u8>,
        // signature can be verified for root and use committee_id indexed pub key for verification
        sig: vector<u8>,
        // typically contains all prices for committee_id
        committee_data: vector<CommitteeFeedWithProof>
    }

    #[allow(unused_field)]
    struct OracleProofV2 has drop {
        // each element of `data` contains one or more price-pairs emanating from a single committees
        data: vector<PriceDetailsWithCommittee>,
    }

    struct MerkleRootHash has key, store {
        id: UID,
        version: u64,
        // mapping of root hash with the timestamp of chain
        root_hashes: EnnumerableSetRing<vector<u8>>
    }

    struct CommitteeFeedWithMultileafProof has drop {
        committee_feeds: vector<PriceData>,
        // Multileaf merkle proof for the `committee_feeds`
        proofs: vector<vector<u8>>,
        flags: vector<bool>
    }

    struct PriceDetailsWithCommitteeData has drop {
        committee_id: u64,
        // root hash of the entire merkle tree used for committee_feed and committee_id verification
        root: vector<u8>,
        // signature can be verified for root and use committee_id indexed pub key for verification
        sig: vector<u8>,
        // typically contains all prices for committee_id
        committee_data: CommitteeFeedWithMultileafProof
    }

    struct OracleProof has drop {
        // each element of `data` contains one or more price-pairs emanating from a multiple committees
        data: vector<PriceDetailsWithCommitteeData>,
    }

    /// Internal - MerkleRootHash implementaion functions
    fun create_merkle_root_hash(ctx: &mut TxContext) {
        transfer::share_object(
            MerkleRootHash {
                id: object::new(ctx), version: VERSION, root_hashes: enumerable_set_ring::new(
                    RING_BUFFER_SIZE,
                    ctx
                )
            }
        );
    }

    /// Its Initial function which will be executed automatically while deployed packages
    fun init(ctx: &mut TxContext) {
        create_merkle_root_hash(ctx);
    }

    /// Extracts relevant information from a PriceData struct
    public fun price_data_split(price_data: &PriceData): (u32, u128, u64, u16, u64) {
        (price_data.pair_index, price_data.value, price_data.timestamp, price_data.decimal, price_data.round)
    }

    entry fun verify_oracle_proof_push(
        dkg_state: &DkgState,
        oracle_holder: &mut OracleHolder,
        merkle_root_hash: &mut MerkleRootHash,
        clock: &Clock,
        committee_ids: vector<u64>,
        roots: vector<vector<u8>>,
        sigs: vector<vector<u8>>,
        pair_indexes: vector<vector<u32>>,
        values: vector<vector<u128>>,
        timestamps: vector<vector<u64>>,
        decimals: vector<vector<u16>>,
        rounds: vector<vector<u64>>,
        proofs: vector<vector<vector<u8>>>,
        flags: vector<vector<bool>>,
        _ctx: &mut TxContext,
    ) {
        SupraSValueFeed::oracle_holder_version_check(oracle_holder);

        // Check vector-type parameters are consistent within the function
        let n = vector::length(&committee_ids);
        assert!(n == vector::length(&roots), EMISSING_LENGTH);
        assert!(n == vector::length(&sigs), EMISSING_LENGTH);
        assert!(n == vector::length(&pair_indexes), EMISSING_LENGTH);
        assert!(n == vector::length(&values), EMISSING_LENGTH);
        assert!(n == vector::length(&timestamps), EMISSING_LENGTH);
        assert!(n == vector::length(&decimals), EMISSING_LENGTH);
        assert!(n == vector::length(&rounds), EMISSING_LENGTH);
        assert!(n == vector::length(&proofs), EMISSING_LENGTH);
        assert!(n == vector::length(&flags), EMISSING_LENGTH);

        let price_details_with_committees = vector[];
        while (!vector::is_empty(&committee_ids)) {
            let committee_id = vector::pop_back(&mut committee_ids);
            let root = vector::pop_back(&mut roots);
            let sig = vector::pop_back(&mut sigs);
            let pair_indexes = vector::pop_back(&mut pair_indexes);
            let values = vector::pop_back(&mut values);
            let timestamps = vector::pop_back(&mut timestamps);
            let decimals = vector::pop_back(&mut decimals);
            let rounds = vector::pop_back(&mut rounds);
            let proofs = vector::pop_back(&mut proofs);
            let flags = vector::pop_back(&mut flags);

            let len = vector::length(&pair_indexes);
            assert!(len == vector::length(&values), EMISSING_LENGTH);
            assert!(len == vector::length(&timestamps), EMISSING_LENGTH);
            assert!(len == vector::length(&decimals), EMISSING_LENGTH);
            assert!(len == vector::length(&rounds), EMISSING_LENGTH);

            let committee_feeds = vector[];
            while (!vector::is_empty(&pair_indexes)) {
                let pair_index = vector::pop_back(&mut pair_indexes);
                let value = vector::pop_back(&mut values);
                let timestamp = vector::pop_back(&mut timestamps);
                let decimal = vector::pop_back(&mut decimals);
                let round = vector::pop_back(&mut rounds);
                vector::push_back(&mut committee_feeds, PriceData { pair_index, value, timestamp, decimal, round })
            };
            vector::reverse(&mut committee_feeds);
            utils::ensure_multileaf_merkle_proof_lengths(proofs, flags, committee_feeds);

            let committee_data = CommitteeFeedWithMultileafProof {
                committee_feeds, flags, proofs
            };
            vector::push_back(&mut price_details_with_committees, PriceDetailsWithCommitteeData {
                committee_id, root, sig, committee_data
            });
        };

        let oracle_proof = OracleProof { data: price_details_with_committees };
        verify_oracle_proof_and_update_data(dkg_state, oracle_holder, merkle_root_hash, clock, oracle_proof);
    }

    /// This function to verify oracle proof which will be used by push and pull both models
    fun verify_oracle_proof_and_update_data(
        dkg_state: &DkgState,
        oracle_holder: &mut OracleHolder,
        merkle_root_hash: &mut MerkleRootHash,
        clock: &Clock,
        oracle_proof: OracleProof,
    ): vector<PriceData> {
        let oracle_proof_data_len = vector::length(&oracle_proof.data);
        let index = 0;
        while (oracle_proof_data_len > index) {
            let data = vector::borrow(&oracle_proof.data, index);

            // Check if the root has been verified earlier. If not, we need to perform verification first. Otherwise, we can skip the verification
            if (!enumerable_set_ring::contains(&merkle_root_hash.root_hashes, data.root)) {
                let sign_result = validator_v2::committee_sign_verification(
                    dkg_state,
                    data.committee_id,
                    data.root,
                    data.sig
                );
                assert!(sign_result, EINVALID_SIGNATURE);
                enumerable_set_ring::add(&mut merkle_root_hash.root_hashes, data.root);
            };
            index = index + 1;
        };

        let price_datas = vector[];
        while (!vector::is_empty(&oracle_proof.data)) {
            let data = vector::pop_back(&mut oracle_proof.data);

            let i = 0;
            let leaves = vector[];
            let committee_feed_length = vector::length(&data.committee_data.committee_feeds);
            while (i < committee_feed_length) {
                let committee_feed = vector::borrow(&data.committee_data.committee_feeds, i);
                vector::push_back(&mut leaves, keccak256(&bcs::to_bytes(committee_feed)));
                i = i + 1;
            };

            assert!(
                utils::is_valid_multileaf_merkle_proof(data.committee_data.proofs, data.committee_data.flags, leaves, data.root),
                EINVALID_MERKLE_PROOF
            );

            while (!vector::is_empty(&data.committee_data.committee_feeds)) {
                let committee_feed = vector::pop_back(&mut data.committee_data.committee_feeds);
                // Update the pair data in storage if it's latest
                SupraSValueFeed::get_oracle_holder_and_upsert_pair_data_v2(
                    oracle_holder,
                    clock,
                    committee_feed.pair_index,
                    committee_feed.value,
                    committee_feed.decimal,
                    (committee_feed.timestamp as u128),
                    committee_feed.round
                );

                // get the latest pair data from oracleholder object
                let pair_index = committee_feed.pair_index;
                let (value, decimal, timestamp, round) = SupraSValueFeed::get_price(oracle_holder, pair_index);
                vector::push_back(
                    &mut price_datas,
                    PriceData { pair_index, value, timestamp: (timestamp as u64), decimal, round }
                );
            };
        };
        price_datas
    }

    /// Verifies the oracle proof and retrieves price data
    public fun verify_oracle_proof(
        dkg_state: &DkgState,
        oracle_holder: &mut OracleHolder,
        merkle_root_hash: &mut MerkleRootHash,
        clock: &Clock,
        oracle_proof_bytes: vector<u8>,
        _ctx: &mut TxContext,
    ): vector<PriceData> {
        SupraSValueFeed::oracle_holder_version_check(oracle_holder);
        let oracle_proof = decode_bytes_to_oracle_proof(oracle_proof_bytes);
        verify_oracle_proof_and_update_data(dkg_state, oracle_holder, merkle_root_hash, clock, oracle_proof)
    }

    /// This function will convert bytes into `OracleProof` type
    fun decode_bytes_to_oracle_proof(bytes: vector<u8>): OracleProof {
        let bcs_bytes = bcs::new(bytes);
        let data_len = bcs::peel_vec_length(&mut bcs_bytes);

        let data = vector[];
        while (data_len > 0) {
            let committee_id = bcs::peel_u64(&mut bcs_bytes);
            let root = bcs::peel_vec_u8(&mut bcs_bytes);
            let sig = bcs::peel_vec_u8(&mut bcs_bytes);
            let committee_feeds = vector[];

            let committee_feed_len = bcs::peel_vec_length(&mut bcs_bytes);
            while (committee_feed_len > 0) {
                let pair_index = bcs::peel_u32(&mut bcs_bytes);
                let value = bcs::peel_u128(&mut bcs_bytes);
                let timestamp = bcs::peel_u64(&mut bcs_bytes);
                let decimal = bcs::peel_u16(&mut bcs_bytes);
                let round = bcs::peel_u64(&mut bcs_bytes);
                vector::push_back(&mut committee_feeds, PriceData { pair_index, value, timestamp, decimal, round });
                committee_feed_len = committee_feed_len - 1;
            };
            let proofs = bcs::peel_vec_vec_u8(&mut bcs_bytes);

            let flags = vector[];
            let flag_len = bcs::peel_vec_length(&mut bcs_bytes);
            while (flag_len > 0) {
                let flag = bcs::peel_bool(&mut bcs_bytes);
                vector::push_back(&mut flags, flag);
                flag_len = flag_len - 1;
            };

            utils::ensure_multileaf_merkle_proof_lengths(proofs, flags, committee_feeds);

            let committee_data = CommitteeFeedWithMultileafProof { committee_feeds, proofs, flags };
            let price_detail_with_committee = PriceDetailsWithCommitteeData { committee_id, root, sig, committee_data };
            vector::push_back(&mut data, price_detail_with_committee);
            data_len = data_len - 1;
        };
        OracleProof { data }
    }

    /// Only Multisig account can perform this action
    /// we are upgrading our package, so in that case, the 'init' function won't be called automatically; we need to do it with migrate call
    entry fun migrate(_: &mut HolderOwnerCap, ctx: &mut TxContext) {
        create_merkle_root_hash(ctx);
    }

    /// Length of the MerkleRootHashes
    public fun merkle_root_hashes_length(merkle_root_hash: &MerkleRootHash): u64 {
        enumerable_set_ring::length(&merkle_root_hash.root_hashes)
    }

    #[test_only]
    fun oracle_proof_data_for_test(): OracleProof {
        OracleProof {
            data: vector[
                PriceDetailsWithCommitteeData {
                    committee_id: 0,
                    root: x"258aeb40afd1fad718b74cd3071e2987daa6fb8d87195765840806063d50a5f3",
                    sig: x"9889809bf3e3278177f0ec481466152f91f8bc6b66cf0563098406430027dcebc078fd124fe1cabd9efbd1bdf4346b25",
                    committee_data: CommitteeFeedWithMultileafProof {
                        committee_feeds: vector[
                            PriceData {
                                pair_index: 0,
                                value: 57253600000000000000000,
                                timestamp: 1723105509092,
                                decimal: 18,
                                round: 1723105509000
                            },
                            PriceData {
                                pair_index: 2,
                                value: 9962000000000000000,
                                timestamp: 1723105509092,
                                decimal: 18,
                                round: 1723105509000
                            }
                        ],
                        proofs: vector[
                            x"a1d35c7d128a20aecf3d6ccc5f72496d7598f8ce850cff4f52fb781f5430c837",
                            x"bed1161f3b666786c7cf70338f90b2cd8640a441bc966f1ecbc8dbf1a7f9b96d",
                            x"c43e8f12c524db4a2ddf8e6f85c23282a64d0e6c324397bb49e135bbc2eef3ea",
                            x"86c981f3030224ecf1210c2b5c3984d2ee6c461df4419d61255dc7ca8ad308b7",
                            x"78622fe6e660d3544b8402c037441b5fc24ecfc0d46b645b8d161c7ee31ce0cc",
                            x"f8d0ceac138401c97055ce0e37aba19e430d9ed54edde6c415daca856f0c6df1",
                            x"44581a54b8ce4e317d9db31a7915fc71d2c5c2aa15328172b1b702f3c2c3f7da",
                            x"94da4ac66a21f9ee3dc23dd55016ddd665c9ace893b8cdc32e4e97f80d33ac55",
                            x"3dd5b5788170fe0be2cf80727467447426b87c2a5da82b9bc38bc40dcd939456"
                        ],
                        flags: vector[ false, false, true, false, false, false, false, false, false, false ]
                    }
                },
                PriceDetailsWithCommitteeData {
                    committee_id: 1,
                    root: x"9a1dd275e66751828048440c3c0f6e6e8c8cd79c5b1e01752e557a1fa4817ccb",
                    sig: x"8b8ab8efa2bdc762846fc462bfe43f28b83f970a0352395335310874c8968e24a33285abbbb8538f9dececb02578661c",
                    committee_data: CommitteeFeedWithMultileafProof {
                        committee_feeds: vector[
                            PriceData {
                                pair_index: 93,
                                value: 47690000000000000,
                                timestamp: 1723105508221,
                                decimal: 18,
                                round: 1723105508000
                            }
                        ],
                        proofs: vector[
                            x"4a0676dbf26a2707a667b1be5964cd1a5a8ebe9bfb6bf6c38f149d5935abedbc",
                            x"68974542c402fca162e0765d7e82cfeed3dc5f2030a32991eea51f004a59d4de",
                            x"7aea0c8c4f46848e68cb19dacc8d4eee20d9975bbd999046dc039935544a18a1",
                            x"4be61e98f022b1477257fbf9c5196b0825367715ce68b9552fb52cf5d276a4dd",
                            x"03c945ef1f827c9ca41ca4e171577ce5d9485ba822ce82b88ac389ec849f7b6c",
                            x"d186c0d92d81485b2ea50c651c846690f632ef1c72bac9b5ce4abda7c99220b2"
                        ],
                        flags: vector[ false, false, false, false, false, false ]
                    }
                }
            ]
        }
    }

    #[test_only]
    fun test_initialize_and_add_committee_public_key(admin: address, scenario: &mut test_scenario::Scenario) {
        use supra_validator::validator_v2::init_for_test;
        use supra_validator::validator::OwnerCap;

        test_scenario::next_tx(scenario, admin);
        {
            init(test_scenario::ctx(scenario));
            init_for_test(test_scenario::ctx(scenario));
            SupraSValueFeed::create_oracle_holder_for_test(test_scenario::ctx(scenario));
        };

        test_scenario::next_tx(scenario, admin);
        {
            let owner_cap = test_scenario::take_from_sender<OwnerCap>(scenario);
            let dkg_state = test_scenario::take_shared<DkgState>(scenario);
            let clock = sui::clock::create_for_testing(test_scenario::ctx(scenario));
            sui::clock::set_for_testing(&mut clock, 1704934230000);

            let committee_0_public_key = vector[162, 162, 134, 119, 60, 217, 97, 45, 123, 58, 170, 102, 92, 39, 158, 150, 8, 139, 19, 183, 123, 147, 154, 191, 122, 219, 71, 109, 163, 102, 66, 239, 162, 110, 47, 16, 222, 55, 181, 43, 213, 7, 158, 233, 213, 143, 7, 102, 11, 10, 155, 138, 200, 216, 117, 140, 197, 34, 250, 27, 86, 203, 169, 89, 116, 149, 18, 184, 177, 231, 142, 102, 230, 157, 161, 168, 203, 34, 204, 149, 143, 150, 26, 162, 187, 45, 190, 174, 218, 148, 41, 113, 86, 94, 131, 66];
            let committee_1_public_key = vector[137, 212, 157, 27, 231, 224, 44, 189, 61, 115, 113, 88, 116, 165, 72, 81, 51, 82, 163, 56, 147, 203, 42, 11, 178, 48, 43, 33, 240, 121, 185, 244, 54, 67, 41, 74, 249, 106, 6, 216, 149, 163, 39, 24, 135, 17, 39, 62, 0, 153, 76, 61, 19, 154, 34, 140, 39, 73, 85, 229, 82, 207, 246, 80, 150, 78, 30, 202, 218, 91, 72, 242, 1, 14, 119, 121, 194, 23, 44, 26, 224, 107, 173, 63, 53, 109, 81, 46, 107, 10, 223, 33, 138, 243, 126, 119];

            validator_v2::add_committee_public_key(
                &mut owner_cap,
                &mut dkg_state,
                &clock,
                0,
                committee_0_public_key,
                test_scenario::ctx(scenario)
            );
            validator_v2::add_committee_public_key(
                &mut owner_cap,
                &mut dkg_state,
                &clock,
                1,
                committee_1_public_key,
                test_scenario::ctx(scenario)
            );

            test_scenario::return_to_sender(scenario, owner_cap);
            test_scenario::return_shared(dkg_state);
            sui::clock::share_for_testing(clock);
        };
    }

    #[test_only]
    fun test_verify_updated_pairs(scenario: &mut test_scenario::Scenario) {
        test_scenario::next_tx(scenario, @0x10cf); // randome user
        {
            let oracle_holder = test_scenario::take_shared<OracleHolder>(scenario);

            let oracle_proof = oracle_proof_data_for_test();
            while (!vector::is_empty(&oracle_proof.data)) {
                let price_details_with_committee = vector::pop_back(&mut oracle_proof.data);
                while (!vector::is_empty(&price_details_with_committee.committee_data.committee_feeds)) {
                    let committee_feed = vector::pop_back(
                        &mut price_details_with_committee.committee_data.committee_feeds
                    );

                    // get price data from oracle_holder and match with the request payload
                    let (price, decimal, timestamp, round) = SupraSValueFeed::get_price(
                        &oracle_holder,
                        committee_feed.pair_index
                    );
                    assert!(committee_feed.value == price, 11);
                    assert!(committee_feed.decimal == decimal, 12);
                    assert!((committee_feed.timestamp as u128) == timestamp, 13);
                    assert!(committee_feed.round == round, 14);
                }
            };

            test_scenario::return_shared(oracle_holder);
        }
    }

    #[test]
    fun test_verify_oracle_proof() {
        let admin = @0x1;

        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        test_initialize_and_add_committee_public_key(admin, scenario);

        test_scenario::next_tx(scenario, admin);
        {
            let dkg_state = test_scenario::take_shared<DkgState>(scenario);
            let oracle_holder = test_scenario::take_shared<OracleHolder>(scenario);
            let merkle_root_hash = test_scenario::take_shared<MerkleRootHash>(scenario);
            let clock = test_scenario::take_shared<Clock>(scenario);
            sui::clock::set_for_testing(&mut clock, 1723105698392);

            let oracle_proof = oracle_proof_data_for_test();
            let bytes = bcs::to_bytes(&oracle_proof);

            verify_oracle_proof(
                &dkg_state,
                &mut oracle_holder,
                &mut merkle_root_hash,
                &clock,
                bytes,
                test_scenario::ctx(scenario)
            );

            test_scenario::return_shared(dkg_state);
            test_scenario::return_shared(oracle_holder);
            test_scenario::return_shared(merkle_root_hash);
            sui::clock::share_for_testing(clock);
        };
        test_verify_updated_pairs(scenario);
        test_scenario::end(scenario_val);
    }

    #[test]
    fun test_verify_oracle_proof_push() {
        let admin = @0x1;

        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        test_initialize_and_add_committee_public_key(admin, scenario);

        test_scenario::next_tx(scenario, admin);
        {
            let dkg_state = test_scenario::take_shared<DkgState>(scenario);
            let oracle_holder = test_scenario::take_shared<OracleHolder>(scenario);
            let merkle_root_hash = test_scenario::take_shared<MerkleRootHash>(scenario);
            let clock = test_scenario::take_shared<Clock>(scenario);
            sui::clock::set_for_testing(&mut clock, 1723105698392);

            let oracle_proof = oracle_proof_data_for_test();

            let committee_ids = vector[];
            let roots = vector[];
            let sigs = vector[];
            let pair_indexes = vector[];
            let values = vector[];
            let timestamps = vector[];
            let decimals = vector[];
            let rounds = vector[];
            let proofs = vector[];
            let flags = vector[];

            let i = 0;
            while (i < vector::length(&oracle_proof.data)) {
                let price_details_with_committees = vector::borrow(&oracle_proof.data, i);
                vector::push_back(&mut committee_ids, price_details_with_committees.committee_id);
                vector::push_back(&mut roots, price_details_with_committees.root);
                vector::push_back(&mut sigs, price_details_with_committees.sig);
                vector::push_back(&mut proofs, price_details_with_committees.committee_data.proofs);
                vector::push_back(&mut flags, price_details_with_committees.committee_data.flags);

                let pair_index = vector[];
                let value = vector[];
                let timestamp = vector[];
                let decimal = vector[];
                let round = vector[];
                let j = 0;
                while (j < vector::length(&price_details_with_committees.committee_data.committee_feeds)) {
                    let committee_feed = vector::borrow(
                        &price_details_with_committees.committee_data.committee_feeds,
                        j
                    );
                    vector::push_back(&mut pair_index, committee_feed.pair_index);
                    vector::push_back(&mut value, committee_feed.value);
                    vector::push_back(&mut timestamp, committee_feed.timestamp);
                    vector::push_back(&mut decimal, committee_feed.decimal);
                    vector::push_back(&mut round, committee_feed.round);
                    j = j + 1;
                };
                vector::push_back(&mut pair_indexes, pair_index);
                vector::push_back(&mut values, value);
                vector::push_back(&mut timestamps, timestamp);
                vector::push_back(&mut decimals, decimal);
                vector::push_back(&mut rounds, round);
                i = i + 1;
            };

            verify_oracle_proof_push(
                &dkg_state,
                &mut oracle_holder,
                &mut merkle_root_hash,
                &clock,
                committee_ids, roots, sigs, pair_indexes, values, timestamps, decimals, rounds, proofs, flags,
                test_scenario::ctx(scenario)
            );

            test_scenario::return_shared(dkg_state);
            test_scenario::return_shared(oracle_holder);
            test_scenario::return_shared(merkle_root_hash);
            sui::clock::share_for_testing(clock);
        };
        test_verify_updated_pairs(scenario);
        test_scenario::end(scenario_val);
    }
}