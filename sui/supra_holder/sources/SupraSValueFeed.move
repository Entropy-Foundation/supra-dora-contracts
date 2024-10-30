// Copyright (c) Supra Oracle.
// SPDX-License-Identifier: MIT

#[allow(unused_field)]
/// Auction:
/// Owner - The owner of the package can perform the `add_public_key` entry function.
/// Free-node - The free-node can perform the `process_cluster` entry function.
/// User - The user can use the `get_price`, `get_prices`, and `extract_price` public functions
///
/// - The Supra Owner deploys the smart contract/package and sets/updates the public key.
/// - The free-node will call `process_cluster` to update the price feed in the respective OracleHolder object.
/// - Users are able to retrieve single or multiple prices from the OracleHolder object using our public function.
module SupraOracle::SupraSValueFeed {

    use sui::event::emit;
    use sui::object::{Self, ID, UID};
    use sui::table::{Self, Table};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use std::vector;
    use sui::clock::{Self, Clock};
    use supra_utils::utils;
    use supra_validator::validator::{Self, DkgState as ValidatorDkgState, ClusterInfo};
    friend SupraOracle::price_data_pull;
    friend SupraOracle::price_data_pull_v2;

    // Track the current version of the module
    const VERSION: u64 = 1;

    /// User Requesting for invalid pair or subscription
    const EINVALID_PAIR: u64 = 1;
    /// Calling functions from the wrong package version
    const EWRONG_ORACLE_HOLDER_VERSION: u64 = 2;
    /// Migration is not an upgrade
    const EUPGRADE_ORACLE_HOLDER: u64 = 3;
    /// Not owner of shared object
    const EORACLE_HOLDER_OWNER: u64 = 4;
    /// PairId1 and PairId2 should not be same
    const EPAIR_ID_SAME: u64 = 5;
    /// Invalid Operation, it should be 0 => Multiplication || 1 => Division
    const EINVALID_OPERATION: u64 = 6;
    /// Invalid decimal, it should not be more than [MAX_DECIMAL]
    const EINVALID_DECIMAL: u64 = 7;
    /// Round should not be scheduled in the future
    const EROUND_IN_FUTURE: u64 = 8;

    /// Keeping the decimal for the derived prices as 18
    const MAX_DECIMAL: u16 = 18;
    /// Time Delta allowance in millisecond
    const TIME_DELTA_ALLOWANCE: u64 = 500;

    /// Capability that grants an owner the right to perform action.
    struct OwnerCap has key { id: UID }

    /// Manage DKG pubkey key to verify BLS signature
    struct DkgState has key, store {
        id: UID,
        public_key: vector<u8>,
    }

    /// Manage price feeds of respective pairs in HashMap/VectorMap
    struct OracleHolder has key, store {
        id: UID,
        version: u64,
        owner: ID,
        feeds: Table<u32, Entry>,
    }

    struct Entry has store, copy, drop {
        value: u128,
        decimal: u16,
        timestamp: u128,
        round: u64
    }

    /// Define MinBlock struct
    struct MinBlock has drop {
        round: vector<u8>,
        timestamp: vector<u8>,
        author: vector<u8>,
        qc_hash: vector<u8>,
        batch_hashes: vector<vector<u8>>,
    }

    /// Define struct for Vote
    struct Vote has drop {
        smr_block: MinBlock,
        round: u64,
    }

    /// Define MinBatch struct
    struct MinBatch has drop {
        protocol: vector<u8>,
        // SPEC: List of keccak256(keccak256(Txn.cluster), Txn.bincodeHash, Txn.sender, Txn.protocol, Txn.tx_sub_type)
        txn_hashes: vector<vector<u8>>,
    }

    /// @notice An SMR Transaction
    struct MinTxn has drop {
        cluster_hashes: vector<vector<u8>>,
        sender: vector<u8>,
        protocol: vector<u8>,
        tx_sub_type: u8,
    }

    /// Define "Signed Coherent Cluster" / scc struct and there child struct
    struct SignedCoherentCluster has drop {
        cc: CoherentCluster,
        qc: vector<u8>, // BlsSignature
        round: u64,
        origin: Origin,
    }
    struct CoherentCluster has copy, drop {
        data_hash: vector<u8>,
        pair: vector<u32>,
        prices: vector<u128>,
        timestamp: vector<u128>,
        decimals: vector<u16>,
    }

    struct Origin has drop {
        id: vector<u8>,
        member_index: u64,
        committee_index: u64
    }

    /// Return type of the price that we are given to c
    struct Price has drop {
        pair: u32,
        value: u128,
        decimal: u16,
        timestamp: u128,
        round: u64
    }

    /// signed coherent cluster processed event
    struct SCCProcessedEvent has drop, copy { hash: vector<u8> }

    /// Migrate version event from_version to to_version
    struct MigrateVersionEvent has drop, copy { from_v: u64, to_v: u64 }

    /// Pair data update/add event
    struct PairDataUpdateEvent has drop, copy { pair: u32, value: u128, decimal: u16, timestamp: u128, round: u64 }

    /// Its Initial function which will be executed automatically while deployed packages
    fun init(ctx: &mut TxContext) {
        let holder_owner_cap = OwnerCap { id: object::new(ctx) };
        let oracle_holder = OracleHolder {
            id: object::new(ctx),
            owner: object::id(&holder_owner_cap),
            version: VERSION,
            feeds: table::new(ctx),
        };
        transfer::transfer(holder_owner_cap, tx_context::sender(ctx));
        transfer::share_object(oracle_holder);
    }

    /// External - free-node use this function
    ///
    /// The process_cluster function is designed to be called by a free-node and it updates the price feed for respective pairs in the OracleHolder object.
    /// It takes multiple input parameters that contain information about the vote, batch, transaction, signed coherent cluster, and other necessary data for verification and updating the price feed.
    ///
    /// Let's break down the function parameters:
    /// dkg_state: &DkgState - A reference to the DkgState object containing the public key used to verify BLS signatures.
    /// oracle_holder: &mut OracleHolder - A mutable reference to the OracleHolder object that stores the price feeds.
    /// Input parameters related to the vote: (incoming parameters are in bcs::to_bytes format, expect vote_round)
    ///     vote_smr_block_round: vector<vector<u8>> - Vector of round that represents the round of SMR blocks in the vote.
    ///     vote_smr_block_timestamp: vector<vector<u8>> - Vector of timestamps that represents the timestamps of SMR blocks in the vote.
    ///     vote_smr_block_author: vector<vector<u8>> - Vector of authors that represents the authors of SMR blocks in the vote.
    ///     vote_smr_block_qc_hash: vector<vector<u8>> - Vector of QC hashes that represents the QC hashes of SMR blocks in the vote.
    ///     vote_smr_block_batch_hashes: vector<vector<vector<u8>>> - Vector of batch hashes that represents the batch hashes of SMR blocks in the vote.
    ///     vote_round: vector<u64> - Vector of round represents the rounds of the vote.
    /// Input parameters related to the batch: (incoming parameters are in bcs::to_bytes format)
    ///     min_batch_protocol: vector<vector<u8>> - Vector of protocols that represents the protocols of the min batches.
    ///     min_batch_txn_hashes: vector<vector<vector<u8>>> - Vector of transaction hashes represents the transaction hashes of the min batches.
    /// Input parameters related to the transaction: (incoming parameters are in bcs::to_bytes format)
    ///     min_txn_cluster_hashes: vector<vector<vector<u8>>> - Vector of cluster hashes that represents the cluster hashes of the min transactions.
    ///     min_txn_sender: vector<vector<u8>> - Vector of senders that represents the senders of the min transactions.
    ///     min_txn_protocol: vector<vector<u8>> - Vector of protocols that represents the protocols of the min transactions.
    ///     min_txn_tx_sub_type: vector<u8> - Vector of transaction subtypes that represents the transaction subtypes of the min transactions.
    /// Input parameters related to the signed coherent cluster (scc):
    ///     scc_data_hash: vector<vector<u8>> - Vector of data hashes that represents the data hashes of the scc.
    ///     scc_pair: vector<vector<u32>> - Vector of pairs that represents the pairs of the scc.
    ///     cc_prices: vector<vector<u128>> - Vector of prices that represents the prices of the scc.
    ///     scc_timestamp: vector<vector<u128>> - Vector of timestamps that represents the timestamps of the scc.
    ///     scc_decimals: vector<vector<u16>> - Vector of decimals that represents the decimals of the scc.
    ///     scc_qc: vector<vector<u8>> - Vector of QC that represents the QC of the scc.
    ///     scc_round: vector<u64> - Vector of rounds that represents the rounds of the scc.
    ///     scc_id: vector<vector<u8>> - Vector of IDs that representing the IDs of the scc.
    ///     scc_member_index: vector<u64> - Vector of member indexes that representis the member indexes of the scc.
    ///     scc_committee_index: vector<u64> - Vector of committee indexes that represents the committee indexes of the scc.
    /// Other input parameters:
    ///     batch_idx: vector<u64> - Vector of u64 values representing the indexes of the batches.
    ///     txn_idx: vector<u64> - Vector of u64 values representing the indexes of the transactions.
    ///     cluster_idx: vector<u64> - Vector of cluster indexes that represents the indexes of the clusters.
    ///     sig: vector<vector<u8>> - Vector of BLS signatures that representins the BLS signatures.
    ///
    /// The function proceeds with the following steps:
    ///     It verifies the integrity of the input parameters and ensures that the oracle_holder version matches the expected version.
    ///     It iterates over the vote data by looping through the input vectors using an index variable i.
    ///     Inside the loop, it retrieves the necessary data for each vote, batch, transaction, and signed coherent cluster using the index i.
    ///     It performs verification checks on the vote, batch, transaction, and signed coherent cluster using helper functions such as vote_verification, batch_verification, transaction_verification, and scc_verification.
    ///     (The threshold signature is performed using the tribe, ensuring its security. Since this payload is threshold signed, leak of one of the private keys of the tribe nodes would not compromise the security of the contract. 2/3 private keys have to be compromised to affect the security.)
    /// These functions validate the data against the provided signatures and hashes.
    ///     If all verification checks pass, it emits an event to indicate that the signed coherent cluster has been processed successfully.
    ///     The function then calls the update_price function to update the price feed in the OracleHolder object using the data from the signed coherent cluster.
    ///     The loop continues until all the vote data has been processed.
    ///
    /// The update_price function updates the price feed in the OracleHolder object by iterating over the pairs in the signed coherent cluster and updating the corresponding entry in the OracleHolder.feeds table.
    /// It compares the timestamp of the new price with the existing price and updates it only if the new timestamp is greater.
    /// Overall, the `process_cluster` function verifies the integrity of the input data and then updates the price feed for respective pairs in the OracleHolder object
    entry fun process_cluster(
        dkg_state: &ValidatorDkgState,
        oracle_holder: &mut OracleHolder,

        vote_smr_block_round: vector<vector<u8>>,
        vote_smr_block_timestamp: vector<vector<u8>>,
        vote_smr_block_author: vector<vector<u8>>,
        vote_smr_block_qc_hash: vector<vector<u8>>,
        vote_smr_block_batch_hashes: vector<vector<vector<u8>>>,
        vote_round: vector<u64>,

        min_batch_protocol: vector<vector<u8>>,
        min_batch_txn_hashes: vector<vector<vector<u8>>>,

        min_txn_cluster_hashes: vector<vector<vector<u8>>>,
        min_txn_sender: vector<vector<u8>>,
        min_txn_protocol: vector<vector<u8>>,
        min_txn_tx_sub_type: vector<u8>,

        scc_data_hash: vector<vector<u8>>,
        scc_pair: vector<vector<u32>>,
        scc_prices: vector<vector<u128>>,
        scc_timestamp: vector<vector<u128>>,
        scc_decimals: vector<vector<u16>>,
        scc_qc: vector<vector<u8>>,
        scc_round: vector<u64>,
        scc_id: vector<vector<u8>>,
        scc_member_index: vector<u64>,
        scc_committee_index: vector<u64>,

        batch_idx: vector<u64>,
        txn_idx: vector<u64>,
        cluster_idx: vector<u64>,
        sig: vector<vector<u8>>,
        _ctx: &mut TxContext,
    ) {

        oracle_holder_version_check(oracle_holder);

        let cluster_info_list = validator::validate_then_get_cluster_info_list(dkg_state,
            vote_smr_block_round, vote_smr_block_timestamp, vote_smr_block_author, vote_smr_block_qc_hash, vote_smr_block_batch_hashes, vote_round,
            min_batch_protocol, min_batch_txn_hashes,
            min_txn_cluster_hashes, min_txn_sender, min_txn_protocol, min_txn_tx_sub_type,
            scc_data_hash, scc_pair, scc_prices, scc_timestamp, scc_decimals, scc_qc, scc_round, scc_id, scc_member_index, scc_committee_index,
            batch_idx, txn_idx, cluster_idx, sig,
        );

        while (!vector::is_empty(&cluster_info_list)) {
            update_price(
                oracle_holder,
                vector::pop_back(&mut cluster_info_list)
            );
        }
    }

    /// Internal - Update the Price feed in the OracleHolder Object
    fun update_price(oracle_holder: &mut OracleHolder, cluster_info: ClusterInfo) {
        let (cc, round) = validator::cluster_info_split(&cluster_info);
        let (pairs, prices, decimals, timestamps) = validator::coherent_cluster_split(cc);

        while (!vector::is_empty(&pairs)) {
            let entry = Entry {
                value: vector::pop_back(&mut prices),
                decimal: vector::pop_back(&mut decimals),
                timestamp: vector::pop_back(&mut timestamps),
                round
            };
            upsert_pair_data(oracle_holder, vector::pop_back(&mut pairs), entry);
        };

        let hash = *validator::oracle_ssc_processed_event(&cluster_info);
        emit(SCCProcessedEvent { hash });
    }

    /// Internal function
    /// If the specified pair already exists in the Oracle Holder, update the entry if the new timestamp is greater.
    /// If the pair does not exist, add a new pair with the provided entry to the Oracle Holder.
    fun upsert_pair_data(oracle_holder: &mut OracleHolder, pair: u32, entry: Entry) {
        if (is_pair_exist(oracle_holder, pair)) {
            let feed = table::borrow_mut(&mut oracle_holder.feeds, pair);
            // Update the price only if "timestamp" is greater than "stored timestamp"
            if (feed.round < entry.round) {
                *feed = entry;
            }
        } else {
            table::add(&mut oracle_holder.feeds, pair, entry);
        };
    }

    /// Internal function
    /// If the new round/timestamp is higher than the current block timestamp, the execution will fail.
    /// If the specified pair already exists in the Oracle Holder, update the entry if the new round is greater.
    /// If the pair does not exist, add a new pair with the provided entry to the Oracle Holder.
    fun upsert_pair_data_v2(oracle_holder: &mut OracleHolder, clock: &Clock, pair: u32, entry: Entry) {
        assert!(entry.round < (clock::timestamp_ms(clock) + TIME_DELTA_ALLOWANCE), EROUND_IN_FUTURE);
        if (is_pair_exist(oracle_holder, pair)) {
            let feed = table::borrow_mut(&mut oracle_holder.feeds, pair);
            // Update the price only if "feed" is greater than "stored feed"
            if (feed.round < entry.round) {
                emit(
                    PairDataUpdateEvent { pair, value: entry.value, timestamp: entry.timestamp, decimal: entry.decimal, round: entry.round }
                );
                *feed = entry;
            }
        } else {
            emit(
                PairDataUpdateEvent { pair, value: entry.value, timestamp: entry.timestamp, decimal: entry.decimal, round: entry.round }
            );
            table::add(&mut oracle_holder.feeds, pair, entry);
        };
    }

    /// Friend function - To upsert pair data
    public(friend) fun get_oracle_holder_and_upsert_pair_data(
        oracle_holder: &mut OracleHolder,
        pair: u32,
        value: u128,
        decimal: u16,
        timestamp: u128,
        round: u64
    ) {
        let entry = Entry { value, decimal, timestamp, round };
        upsert_pair_data(oracle_holder, pair, entry);
    }

    /// Friend function - To upsert pair data
    public(friend) fun get_oracle_holder_and_upsert_pair_data_v2(
        oracle_holder: &mut OracleHolder,
        clock: &Clock,
        pair: u32,
        value: u128,
        decimal: u16,
        timestamp: u128,
        round: u64
    ) {
        let entry = Entry { value, decimal, timestamp, round };
        upsert_pair_data_v2(oracle_holder, clock, pair, entry);
    }

    /// Function which checks that is pair index is exist in OracleHolder
    public fun is_pair_exist(oracle_holder: &OracleHolder, pair_index: u32): bool {
        table::contains(&oracle_holder.feeds, pair_index)
    }

    /// External public function
    /// It will return the priceFeedData value for that particular tradingPair
    public fun get_price(oracle_holder: &OracleHolder, pair: u32): (u128, u16, u128, u64) {
        oracle_holder_version_check(oracle_holder);
        assert!(table::contains(&oracle_holder.feeds, pair), EINVALID_PAIR);
        let feed = table::borrow(&oracle_holder.feeds, pair);
        (feed.value, feed.decimal, feed.timestamp, feed.round)
    }

    /// External public function
    /// It will return the priceFeedData value for that multiple tradingPair
    /// If any of the pairs do not exist in the OracleHolder, an empty vector will be returned for that pair.
    /// If a client requests 10 pairs but only 8 pairs exist, only the available 8 pairs' price data will be returned.
    public fun get_prices(oracle_holder: &OracleHolder, pairs: vector<u32>): vector<Price> {
        oracle_holder_version_check(oracle_holder);
        let prices: vector<Price> = vector[];

        while (!vector::is_empty(&pairs)) {
            let pair = vector::pop_back(&mut pairs);
            if (is_pair_exist(oracle_holder, pair)) {
                let feed = table::borrow(&oracle_holder.feeds, pair);
                vector::push_back(
                    &mut prices,
                    Price { pair, value: feed.value, decimal: feed.decimal, timestamp: feed.timestamp, round: feed.round }
                );
            };
        };
        prices
    }

    /// External public function
    /// It will return the extracted price value for the Price struct
    public fun extract_price(price: &Price): (u32, u128, u16, u128, u64) {
        (price.pair, price.value, price.decimal, price.timestamp, price.round)
    }

    /// This function will transfer ownership from the account to the specified(multisig) address.
    entry fun transfer_authority(owner_cap: OwnerCap, to: address, _ctx: &mut TxContext) {
        transfer::transfer(owner_cap, to);
    }

    /// Only Owner can perform this action
    /// Introduce a migrate function which update the version of the shared object
    entry fun migrate(owner_cap: &OwnerCap, oracle_holder: &mut OracleHolder, _ctx: &mut TxContext) {
        assert!(oracle_holder.owner == object::id(owner_cap), EORACLE_HOLDER_OWNER);
        assert!(oracle_holder.version < VERSION, EUPGRADE_ORACLE_HOLDER);
        emit(MigrateVersionEvent { from_v: oracle_holder.version, to_v: VERSION });
        oracle_holder.version = VERSION;
    }

    /// External public function.
    /// This function will help to find the prices of the derived pairs
    /// Derived pairs are the one whose price info is calculated using two compatible pairs using either multiplication or division.
    /// Return values in tuple
    ///     1. derived_price : u32
    ///     2. decimal : u16
    ///     3. round-difference : u64
    ///     4. `"pair_id1" as compared to "pair_id2"` : u8 (Where 0=>EQUAL, 1=>LESS, 2=>GREATER)
    public fun get_derived_price(
        oracle_holder: &OracleHolder,
        pair_id1: u32,
        pair_id2: u32,
        operation: u8
    ): (u128, u16, u64, u8) {
        oracle_holder_version_check(oracle_holder);
        assert!(pair_id1 != pair_id2, EPAIR_ID_SAME);
        assert!((operation <= 1), EINVALID_OPERATION);

        let (value1, decimal1, _timestamp1, round1) = get_price(oracle_holder, pair_id1);
        let (value2, decimal2, _timestamp2, round2) = get_price(oracle_holder, pair_id2);
        let value1 = (value1 as u256);
        let value2 = (value2 as u256);

        // used variable name with `_` to remove compilation warning
        let _derived_price: u256 = 0;

        // operation 0 it means multiplication
        if (operation == 0) {
            let sum_decimal_1_2 = decimal1 + decimal2;
            if (sum_decimal_1_2 > MAX_DECIMAL) {
                _derived_price = (value1 * value2) / (utils::calculate_power(10, (sum_decimal_1_2 - MAX_DECIMAL)));
            } else {
                _derived_price = (value1 * value2) * (utils::calculate_power(10, (MAX_DECIMAL - sum_decimal_1_2)));
            }
        } else {
            _derived_price = (scale_price(value1, decimal1) * (utils::calculate_power(10, MAX_DECIMAL))) / scale_price(
                value2,
                decimal2
            )
        };

        let base_compare_to_quote = 0; // default consider as equal
        let round_difference = if (round1 > round2) {
            base_compare_to_quote = 2;
            round1 - round2
        } else if (round1 < round2) {
            base_compare_to_quote = 1;
            round2 - round1
        } else { 0 };
        ((_derived_price as u128), MAX_DECIMAL, round_difference, base_compare_to_quote)
    }

    /// Scales a price value by adjusting its decimal precision.
    fun scale_price(price: u256, decimal: u16): u256 {
        assert!(decimal <= MAX_DECIMAL, EINVALID_DECIMAL);
        if (decimal == MAX_DECIMAL) { price }
        else { price * (utils::calculate_power(10, (MAX_DECIMAL - decimal))) }
    }

    public(friend) fun oracle_holder_version_check(oracle_holder: &OracleHolder) {
        assert!(oracle_holder.version == VERSION, EWRONG_ORACLE_HOLDER_VERSION);
    }

    #[test_only]
    public fun create_oracle_holder_for_test(ctx: &mut TxContext) {
        let holder_owner_cap = OwnerCap { id: object::new(ctx) };
        let oracle_holder = OracleHolder {
            id: object::new(ctx), owner: object::id(
                &holder_owner_cap
            ), version: VERSION, feeds: table::new(ctx)
        };
        transfer::transfer(holder_owner_cap, tx_context::sender(ctx));
        transfer::share_object(oracle_holder);
    }
}
