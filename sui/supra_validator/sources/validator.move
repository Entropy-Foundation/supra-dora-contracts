/// Smart contract for validating and processing transactions in a decentralized network.
/// This module defines the validator logic for ensuring the integrity and validity of various components,
/// including votes, batches, transactions, and coherent clusters, within a decentralized network.
///
/// Auction:
/// Owner : In current version only `update_public_key` can perform this action
/// Free-node / User : The User/free-node can use `validate_then_get_cluster_info_list` and rest of the public functions
module supra_validator::validator {

    use std::bcs;
    use std::vector;
    use sui::hash::keccak256;
    use sui::bls12381;
    use sui::transfer;
    use sui::object;
    use sui::tx_context::{Self, TxContext};
    use sui::object::UID;
    use sui::event::emit;
    friend supra_validator::validator_v2;

    /// Length miss match
    const EMISSING_LENGTH: u64 = 11;
    /// Incorrect publickey or signature
    const EINVALID_SIGNATURE: u64 = 12;
    /// Batch not verified
    const EINVALID_BATCH: u64 = 13;
    /// Transaction not verified
    const EINVALID_TRANSACTION: u64 = 14;
    /// Cluster not verified
    const EINVALID_CLUSTER: u64 = 15;
    /// The DKG is either not set or disabled
    const EDKG_NOT_SET: u64 = 16;
    /// Invalid Public key lnput
    const EINVALID_PUBLIC_KEY: u64 = 17;

    /// define public key length
    const PUBLIC_KEY_LENGTH: u64 = 96;

    /// Capability that grants an owner the right to perform action.
    struct OwnerCap has key { id: UID }

    /// Update Public Key event
    struct UpdatePublicKeyEvent has drop, copy { public_key: vector<u8> }

    /// Manage DKG pubkey key to verify BLS signature
    struct DkgState has key, store {
        id: UID,
        public_key: vector<u8>,
        is_set: bool,
    }

    struct ClusterInfo has drop {
        cc: CoherentCluster,
        round: u64,
        cluster_hashes: vector<vector<u8>>,
        cluster_idx: u64,
    }

    /// Define "Signed Coherent Cluster" / scc struct and there child struct
    struct SignedCoherentCluster has drop {
        cc: CoherentCluster,
        qc: vector<u8>, // BlsSignature
        round: u64,
        origin: Origin,
    }

    struct Origin has drop {
        id: vector<u8>,
        member_index: u64,
        committee_index: u64
    }

    struct CoherentCluster has drop {
        data_hash: vector<u8>,
        pair: vector<u32>,
        prices: vector<u128>,
        timestamp: vector<u128>,
        decimals: vector<u16>,
    }

    /// @notice An SMR Transaction
    struct MinTxn has drop {
        cluster_hashes: vector<vector<u8>>,
        sender: vector<u8>,
        protocol: vector<u8>,
        tx_sub_type: u8,
    }

    /// Define MinBatch struct
    struct MinBatch has drop {
        protocol: vector<u8>,
        // SPEC: List of keccak256(keccak256(Txn.cluster), Txn.bincodeHash, Txn.sender, Txn.protocol, Txn.tx_sub_type)
        txn_hashes: vector<vector<u8>>,
    }

    /// Define struct for Vote
    struct Vote has drop {
        smr_block: MinBlock,
        round: u64,
    }

    /// Define MinBlock struct
    struct MinBlock has drop {
        round: vector<u8>,
        timestamp: vector<u8>,
        author: vector<u8>,
        qc_hash: vector<u8>,
        batch_hashes: vector<vector<u8>>,
    }

    /// Its Initial function which will be executed automatically while deployed packages
    /// deployment should only done from admin account (not freenode)
    fun init(ctx: &mut TxContext) {
        let owner_cap = OwnerCap { id: object::new(ctx) };
        transfer::transfer(owner_cap, tx_context::sender(ctx));
        let dkg_state = DkgState { id: object::new(ctx), public_key: vector[], is_set: false };
        transfer::share_object(dkg_state)
    }

    /// Extract public_key from dkg_state object - This function might be useful in future
    public fun get_public_key(dkg_state: &DkgState): vector<u8> {
        assert!(dkg_state.is_set, EDKG_NOT_SET);
        dkg_state.public_key
    }

    /// check that all the arguments has consistant length and then validate
    public fun validate_then_get_cluster_info_list(
        dkg_state: &DkgState,
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
    ): vector<ClusterInfo> {
        assert!(dkg_state.is_set, EDKG_NOT_SET);

        // Check vector-type parameters are consistent within the function
        let n = vector::length(&vote_smr_block_round);
        assert!(n == vector::length(&vote_smr_block_timestamp), EMISSING_LENGTH);
        assert!(n == vector::length(&vote_smr_block_author), EMISSING_LENGTH);
        assert!(n == vector::length(&vote_smr_block_qc_hash), EMISSING_LENGTH);
        assert!(n == vector::length(&vote_smr_block_batch_hashes), EMISSING_LENGTH);
        assert!(n == vector::length(&vote_round), EMISSING_LENGTH);
        assert!(n == vector::length(&min_batch_protocol), EMISSING_LENGTH);
        assert!(n == vector::length(&min_batch_txn_hashes), EMISSING_LENGTH);
        assert!(n == vector::length(&min_txn_cluster_hashes), EMISSING_LENGTH);
        assert!(n == vector::length(&min_txn_sender), EMISSING_LENGTH);
        assert!(n == vector::length(&min_txn_protocol), EMISSING_LENGTH);
        assert!(n == vector::length(&min_txn_tx_sub_type), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_data_hash), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_pair), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_prices), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_timestamp), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_decimals), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_qc), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_round), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_id), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_member_index), EMISSING_LENGTH);
        assert!(n == vector::length(&scc_committee_index), EMISSING_LENGTH);
        assert!(n == vector::length(&batch_idx), EMISSING_LENGTH);
        assert!(n == vector::length(&txn_idx), EMISSING_LENGTH);
        assert!(n == vector::length(&cluster_idx), EMISSING_LENGTH);
        assert!(n == vector::length(&sig), EMISSING_LENGTH);

        let public_key = dkg_state.public_key;
        let cluster_info_list = vector[];
        while (!vector::is_empty(&vote_smr_block_round)) {
            // vote
            let vote_smr_block_round_element = vector::pop_back(&mut vote_smr_block_round);
            let vote_smr_block_timestamp_element = vector::pop_back(&mut vote_smr_block_timestamp);
            let vote_smr_block_author_element = vector::pop_back(&mut vote_smr_block_author);
            let vote_smr_block_qc_hash_element = vector::pop_back(&mut vote_smr_block_qc_hash);
            let vote_smr_block_batch_hashes_element = vector::pop_back(&mut vote_smr_block_batch_hashes);
            let vote_round_element = vector::pop_back(&mut vote_round);
            let sig_element = vector::pop_back(&mut sig);

            let min_block = MinBlock { round: vote_smr_block_round_element, timestamp: vote_smr_block_timestamp_element, author: vote_smr_block_author_element, qc_hash: vote_smr_block_qc_hash_element, batch_hashes: vote_smr_block_batch_hashes_element };

            let vote = Vote {
                smr_block: min_block,
                round: vote_round_element
            };

            // Verification of the vote
            let vote_verified = vote_verification(public_key, &vote, sig_element);
            assert!(vote_verified, EINVALID_SIGNATURE);

            // batch
            let min_batch_protocol_element = vector::pop_back(&mut min_batch_protocol);
            let min_batch_txn_hashes_element = vector::pop_back(&mut min_batch_txn_hashes);
            let batch_idx_element = vector::pop_back(&mut batch_idx);

            let min_batch = MinBatch { protocol: min_batch_protocol_element, txn_hashes: min_batch_txn_hashes_element };

            // Verification of the batch
            let batch_verified = batch_verification(&min_batch, &vote.smr_block.batch_hashes, batch_idx_element);
            assert!(batch_verified, EINVALID_BATCH);

            // transaction
            let min_txn_cluster_hashes_element = vector::pop_back(&mut min_txn_cluster_hashes);
            let min_txn_sender_element = vector::pop_back(&mut min_txn_sender);
            let min_txn_protocol_element = vector::pop_back(&mut min_txn_protocol);
            let min_txn_tx_sub_type_element = vector::pop_back(&mut min_txn_tx_sub_type);
            let min_txn = MinTxn { cluster_hashes: min_txn_cluster_hashes_element, sender: min_txn_sender_element, protocol: min_txn_protocol_element, tx_sub_type: min_txn_tx_sub_type_element };
            let txn_idx_element = vector::pop_back(&mut txn_idx);

            // Verification of the transaction
            let transaction_verified = transaction_verification(&min_txn, &min_batch.txn_hashes, txn_idx_element);
            assert!(transaction_verified, EINVALID_TRANSACTION);

            // signed coherent cluster
            let scc_data_hash_element = vector::pop_back(&mut scc_data_hash);
            let scc_pair_element = vector::pop_back(&mut scc_pair);
            let scc_prices_element = vector::pop_back(&mut scc_prices);
            let scc_timestamp_element = vector::pop_back(&mut scc_timestamp);
            let scc_decimals_element = vector::pop_back(&mut scc_decimals);
            let scc_qc_element = vector::pop_back(&mut scc_qc);
            let scc_round_element = vector::pop_back(&mut scc_round);
            let scc_id_element = vector::pop_back(&mut scc_id);
            let scc_member_index_element = vector::pop_back(&mut scc_member_index);
            let scc_committee_index_element = vector::pop_back(&mut scc_committee_index);
            let cluster_idx_element = vector::pop_back(&mut cluster_idx);

            let scc = SignedCoherentCluster {
                cc: CoherentCluster { data_hash: scc_data_hash_element, pair: scc_pair_element, prices: scc_prices_element, timestamp: scc_timestamp_element, decimals: scc_decimals_element },
                qc: scc_qc_element, round: scc_round_element, origin: Origin { id: scc_id_element, member_index: scc_member_index_element, committee_index: scc_committee_index_element }
            };

            // Verification of the signed coherent cluster
            let scc_verified = scc_verification(&scc, &min_txn.cluster_hashes, cluster_idx_element);
            assert!(scc_verified, EINVALID_CLUSTER);

            let cluster_info = ClusterInfo {
                cc: CoherentCluster { data_hash: scc_data_hash_element, pair: scc_pair_element, prices: scc_prices_element, timestamp: scc_timestamp_element, decimals: scc_decimals_element },
                round: vote_round_element,
                cluster_hashes: min_txn.cluster_hashes,
                cluster_idx: cluster_idx_element,
            };
            vector::push_back(&mut cluster_info_list, cluster_info);
        };
        cluster_info_list
    }

    /// Only Owner can perform this action
    /// it will update the existing object dkg public_key
    entry fun update_public_key(
        _: &mut OwnerCap,
        dkg_state: &mut DkgState,
        public_key: vector<u8>,
        _ctx: &mut TxContext
    ) {
        assert!(vector::length(&public_key) == PUBLIC_KEY_LENGTH, EINVALID_PUBLIC_KEY);
        dkg_state.public_key = public_key;
        dkg_state.is_set = true;
        emit(UpdatePublicKeyEvent { public_key });
    }

    /// Only Owner can perform this action
    /// it will disable existing dkg public key
    entry fun disable_public_key(_: &mut OwnerCap, dkg_state: &mut DkgState, _ctx: &mut TxContext) {
        dkg_state.public_key = vector[];
        dkg_state.is_set = false;
        emit(UpdatePublicKeyEvent { public_key: vector[] });
    }

    // decompose coherent cluster
    public fun coherent_cluster_split(cc: &CoherentCluster): (vector<u32>, vector<u128>, vector<u16>, vector<u128>) {
        (cc.pair, cc.prices, cc.decimals, cc.timestamp)
    }

    // decompose cluster info
    public fun cluster_info_split(cluster_info: &ClusterInfo): (&CoherentCluster, u64) {
        (&cluster_info.cc, cluster_info.round)
    }

    public fun oracle_ssc_processed_event(cluster_info: &ClusterInfo): &vector<u8> {
        vector::borrow(&cluster_info.cluster_hashes, cluster_info.cluster_idx)
    }

    /// Internal - Verification of the signed coherent cluster
    fun scc_verification(scc: &SignedCoherentCluster, cluster_hashes: &vector<vector<u8>>, cluster_idx: u64): bool {
        let scc_hash = hash_scc(scc);
        let get_cluster_hashes = vector::borrow(cluster_hashes, cluster_idx);
        get_cluster_hashes == &scc_hash
    }

    /// Internal - vote verification = Create smr_hash_vote as the message and verify the signature against the public key
    fun vote_verification(public_key: vector<u8>, vote: &Vote, sign: vector<u8>): bool {
        let msg = smr_hash_vote(vote);
        verify_signature(public_key, msg, sign)
    }

    /// Internal - Internal function that calls bls12381 to verify the signature
    fun verify_signature(public_key: vector<u8>, msg: vector<u8>, signature: vector<u8>): bool {
        bls12381::bls12381_min_sig_verify(&signature, &public_key, &msg)
    }

    /// Internal - Create hash from smr keccak256(`smr_block.batch_hashes`) + keccak256(`smr_block - round,timestamp,auther,qc`) + keccak256(`round_le`)
    fun smr_hash_vote(vote: &Vote): vector<u8> {
        // vote.smr_block.batch_hashes convert into bytes and then `keccak256`
        let bcs_batches_hashes: vector<u8> = vector[];
        supra_utils::utils::vector_flatten_concat(&mut bcs_batches_hashes, vote.smr_block.batch_hashes);

        // let bcs_batches_hash = bcs::to_bytes(&vote.smr_block.batch_hashes);
        let batches_hash = keccak256(&bcs_batches_hashes);

        let block_data = vote.smr_block.round;
        vector::append(&mut block_data, vote.smr_block.timestamp);
        vector::append(&mut block_data, vote.smr_block.author);
        vector::append(&mut block_data, vote.smr_block.qc_hash);

        // append `batches_hash` into bcs_batch_hashes
        vector::append(&mut block_data, batches_hash);

        // keccak256 of `bcs_batch_hashes`
        let block_hash = &mut keccak256(&block_data);

        // append smr_block.round into bcs_batch_hashes
        vector::append(block_hash, bcs::to_bytes(&vote.round));
        keccak256(block_hash)
    }

    /// Internal - create hash of keccak256(SignedCoherentCluster)
    fun hash_scc(scc: &SignedCoherentCluster): vector<u8> {
        let bcs_scc = bcs::to_bytes(scc);
        keccak256(&bcs_scc)
    }

    /// Internal - create hash of keccak256(batch.protocol, keccak256(txns_hash))
    fun hash_min_batch(min_batch: &MinBatch): vector<u8> {
        let bcs_txns_hash: vector<u8> = vector[];
        supra_utils::utils::vector_flatten_concat(&mut bcs_txns_hash, min_batch.txn_hashes);
        let txns_hash = keccak256(&bcs_txns_hash);

        let bcs_protocol = min_batch.protocol;

        vector::append(&mut bcs_protocol, txns_hash);
        keccak256(&bcs_protocol)
    }

    /// Internal - Verification of the batch
    fun batch_verification(min_batch: &MinBatch, batch_hashes: &vector<vector<u8>>, batch_idx: u64): bool {
        let batch_hash = hash_min_batch(min_batch);
        let get_batch_hash = vector::borrow(batch_hashes, batch_idx);
        get_batch_hash == &batch_hash
    }

    /// Internal - Create hash of keccak256(bcs_hash, sender, tx_sub_type)
    fun hash_min_txn(min_txn: &MinTxn): vector<u8> {
        let bcs_hashes: vector<u8> = vector[];
        supra_utils::utils::vector_flatten_concat(&mut bcs_hashes, min_txn.cluster_hashes);
        vector::append(&mut bcs_hashes, min_txn.sender);
        vector::append(&mut bcs_hashes, min_txn.protocol);
        vector::append(&mut bcs_hashes, vector[min_txn.tx_sub_type]);

        keccak256(&bcs_hashes)
    }

    /// Internal - Verification of the transaction
    fun transaction_verification(min_txn: &MinTxn, txn_hashes: &vector<vector<u8>>, txn_idx: u64): bool {
        let tx_hash = hash_min_txn(min_txn);
        let get_tx_hash = vector::borrow(txn_hashes, txn_idx);
        get_tx_hash == &tx_hash
    }

    /// This function will transfer ownership from the account to the specified(multisig) address.
    entry fun transfer_authority(owner_cap: OwnerCap, to: address, _ctx: &mut TxContext) {
        transfer::transfer(owner_cap, to);
    }

    #[test_only]
    public fun create_dkg_state_for_test(ctx: &mut TxContext) {
        let owner_cap = OwnerCap { id: object::new(ctx) };
        transfer::transfer(owner_cap, tx_context::sender(ctx));
    }

    #[test_only]
    public fun set_public_key_for_test(public_key: vector<u8>, ctx: &mut TxContext) {
        let dkg_state = DkgState { id: object::new(ctx), public_key, is_set: false };
        transfer::share_object(dkg_state)
    }

    #[test]
    fun check_vote_verification() {
        use sui::hex;
        use sui::test_scenario;
        let admin = @0x1;

        let round = hex::decode(b"00000000000000e6");
        let timestamp = hex::decode(b"000000000000000000000187dc76baeb");
        let author = hex::decode(b"8f1c91851b02fae47080889cc1614adca89efe64f39a6ec4b8dbf43e2902bcd3");
        let qc_hash = hex::decode(b"3c63699e98f015b696a5005041fe9a9819827ab36bd7eab5fbac9671c1d3d384");
        let batch_hashes = vector[hex::decode(b"b01e1cfbc6bb5b04dba2c09a271acf37ca480df379cba926603ba7a31ef64c4a")];
        let vote_round = 230;
        let sig = hex::decode(b"8861e505603cd10968ae0eff41000296b7a44569ae66b3875c608a20b06dece871e2550c0e9dec35d71d08790d2b10aa");
        let public_key = hex::decode(b"a8f329778e9442369451db74a2c168c3065ec5094af78a7ce9eb1d9d372dbd0d32f6ae9cdfbd303cb8da5dd35b5fd4ae057eb0172f1d20e821013dbdfe0f0c7e775011fde0f08c6a72eecc5d3a39ac1d3accec977e879f6fbf25188f74188ec5");

        let vote = Vote {
            smr_block: MinBlock { round, timestamp, author, qc_hash, batch_hashes },
            round: vote_round
        };

        let scenario_val = test_scenario::begin(admin);

        // Verify Vote
        let vote_verified = vote_verification(public_key, &vote, sig);
        assert!(vote_verified, 1);

        test_scenario::end(scenario_val);
    }

    #[test]
    fun check_batch_verification() {
        use sui::hex;

        let protocol = hex::decode(b"03000000000000000000");
        let txn_hashes = vector[
            hex::decode(b"26619fbb8d13059d8f2b918c9bae5442d42a0bfb74da1d6f9d453007eba0bfa4"),
            hex::decode(b"693fdfe52a58d7372e8bc2e25878f3423a1b2a3239887bfb09304a22f769ff62")
        ];
        let batch_hashes = vector[hex::decode(b"b01e1cfbc6bb5b04dba2c09a271acf37ca480df379cba926603ba7a31ef64c4a")];
        let batch_idx = 0;
        let min_batch = MinBatch { protocol, txn_hashes };

        // Verify Batch
        let batch_verified = batch_verification(&min_batch, &batch_hashes, batch_idx);
        assert!(batch_verified, 2);
    }

    #[test]
    fun check_transaction_verification() {
        use sui::hex;

        let cluster_hashes = vector[
            hex::decode(b"46ce6bc0f58a1509e14d41a03c746dc0aeff1eb6561deaad438debbf0ab8ecd2"),
            hex::decode(b"cd15e406811017e1e5475f3190d0ab5ccf32bcf6649e6c3a1e5fa267b3c2dc23")
        ];
        let sender = hex::decode(b"43a75af8373e0ff0a24a8bdb5fc8740680fcee95a1f61984c5f62bad72ac2ab5");
        let protocol = hex::decode(b"03000000000000000000");
        let tx_sub_type = 0;
        let min_txn = MinTxn { cluster_hashes, sender, protocol, tx_sub_type };
        let txn_hashes = vector[
            hex::decode(b"26619fbb8d13059d8f2b918c9bae5442d42a0bfb74da1d6f9d453007eba0bfa4"),
            hex::decode(b"693fdfe52a58d7372e8bc2e25878f3423a1b2a3239887bfb09304a22f769ff62")
        ];
        let txn_idx = 0;

        // Verify Transaction
        let transaction_verified = transaction_verification(&min_txn, &txn_hashes, txn_idx);
        assert!(transaction_verified, 3);
    }

    #[test]
    fun check_signed_coherent_cluster() {
        use sui::hex;
        let data_hash = hex::decode(b"1ff5f299faf6bcf967c950b25241575a7244695ed92a7b07f03c9e84aa171967");
        let pair = vector[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 ];
        let prices = vector[ 28083940000000000000000, 1832980000000000000000, 6874000000000000000, 78290000000000000, 118740000000000000000, 16660000000000000000, 5672000000000000000, 68700000000000000000, 5285300000000000000, 88170000000000000000, 21975000000000000000, 705500000000000000000, 39670000000000000000, 1009000000000000000, 462430000000000000, 68320000000000000, 385490000000000000, 11000000000000000000, 2814371000000, 183702000000 ];
        let timestamp = vector[ 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044, 1683030981044 ];
        let decimals = vector[ 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 8, 8 ];
        let qc = hex::decode(b"0313a509e777b6448275c027f70a12bc9b2c2eae7080466712f3e9323e9e5e7c73797820e459b8ebfff41c8909a1986b6e03095f75a070dc8cb18b2a0b7616dd5fb658a50ebd08973b005cc50794b6d85b57a10eba056747616a40c4ca92ab0421bb0127a8ec3a286614a1918677c975e30e54d619bdb5b6dd50910b98b913b1984ab0d31316cdd37e1cad3d0261a095c5c8031670e8d7435a13c4828240b364d5e00c58efbff7bc52dbf5dcc3071edca81f6b");

        let round = 1683030981000;
        let id = hex::decode(b"43a75af8373e0ff0a24a8bdb5fc8740680fcee95a1f61984c5f62bad72ac2ab5");
        let member_index = 0;
        let committee_index = 0;

        let scc = SignedCoherentCluster {
            cc: CoherentCluster { data_hash, pair, prices, timestamp, decimals },
            qc, round, origin: Origin { id, member_index, committee_index }
        };

        let cluster_hashes = vector[
            hex::decode(b"46ce6bc0f58a1509e14d41a03c746dc0aeff1eb6561deaad438debbf0ab8ecd2"),
            hex::decode(b"cd15e406811017e1e5475f3190d0ab5ccf32bcf6649e6c3a1e5fa267b3c2dc23")
        ];
        let cluster_idx: u64 = 1;

        // Verify Signed Coherent Cluster
        let scc_verified = scc_verification(&scc, &cluster_hashes, cluster_idx);
        assert!(scc_verified, 4);
    }
}
