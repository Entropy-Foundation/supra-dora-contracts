/// This module provides functionality for pulling and verifying price data from multiple clusters and extracting relevant information.
/// Action:
/// User: The User can access `verify_oracle_proof` and `price_data_split` function
module SupraOracle::price_data_pull {

    use std::vector;
    use sui::tx_context::TxContext;
    use SupraOracle::SupraSValueFeed::{Self, OracleHolder};
    use supra_validator::validator::{Self, DkgState};

    /// Length miss match
    const EMISSING_LENGTH: u64 = 11;

    /// Represents price data with information about the pair, price, decimal, timestamp, and stale value status
    struct PriceData has copy, drop {
        pair_index: u32,
        value: u128,
        decimal: u16,
        timestamp: u128,
        round: u64,
    }

    /// Extracts relevant information from a PriceData struct
    public fun price_data_split(price_data: &PriceData) : (u32, u128, u16, u64) {
        (price_data.pair_index, price_data.value, price_data.decimal, price_data.round)
    }

    /// Verifies the oracle proof and retrieves price data from multiple clusters.
    public fun verify_oracle_proof(
        dkg_state: &DkgState,
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
        pair_mask: vector<vector<bool>>,

        _ctx: &mut TxContext,
    ) : vector<PriceData> {
        SupraSValueFeed::oracle_holder_version_check(oracle_holder);
        // length match only for pair_mask here, as because of the length validation has already been done validator contract
        assert!(vector::length(&vote_smr_block_round) == vector::length(&pair_mask), EMISSING_LENGTH);

        // verify the payload and signature
        let _cluster_info_list = validator::validate_then_get_cluster_info_list(dkg_state,
            vote_smr_block_round, vote_smr_block_timestamp, vote_smr_block_author, vote_smr_block_qc_hash, vote_smr_block_batch_hashes, vote_round,
            min_batch_protocol, min_batch_txn_hashes,
            min_txn_cluster_hashes, min_txn_sender, min_txn_protocol, min_txn_tx_sub_type,
            scc_data_hash, scc_pair, scc_prices, scc_timestamp, scc_decimals, scc_qc, scc_round, scc_id, scc_member_index, scc_committee_index,
            batch_idx, txn_idx, cluster_idx, sig,
        );

        let price_datas = vector[];
        while (!vector::is_empty(&pair_mask)) {
            let pair_masks = vector::pop_back(&mut pair_mask);
            let scc_pair_element = vector::pop_back(&mut scc_pair);
            let scc_prices_element = vector::pop_back(&mut scc_prices);
            let scc_decimals_element = vector::pop_back(&mut scc_decimals);
            let scc_timestamp_element = vector::pop_back(&mut scc_timestamp);
            let scc_round_element = vector::pop_back(&mut scc_round);

            while (!vector::is_empty(&pair_masks)) {
                let pair_index = vector::pop_back(&mut scc_pair_element);
                let pair_values = vector::pop_back(&mut scc_prices_element);
                let pair_decimals = vector::pop_back(&mut scc_decimals_element);
                let pair_timestamp = vector::pop_back(&mut scc_timestamp_element);

                if (vector::pop_back(&mut pair_masks)) {
                    SupraSValueFeed::get_oracle_holder_and_upsert_pair_data(oracle_holder, pair_index, pair_values, pair_decimals, pair_timestamp, scc_round_element);

                    // get the latest pair data from oracleholder object
                    let (value, decimal, timestamp, round) = SupraSValueFeed::get_price(oracle_holder, pair_index);
                    vector::push_back(&mut price_datas, PriceData { pair_index, value, decimal, timestamp, round });
                }
            }
        };
        price_datas
    }
}
