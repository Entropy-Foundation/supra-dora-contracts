module supra_utils::utils {
    use std::vector;
    use sui::hash::keccak256;

    /// Undefined expression
    const EUNDEFIND_EXP: u64 = 1;
    /// bytes length is not same to compare
    const EINVALID_BYTES_LENGTH: u64 = 2;
    /// bytes length is 0
    const EEMPTY_BYTES: u64 = 3;
    /// The index into the vector is out of bounds
    const EINDEX_OUT_OF_BOUNDS: u64 = 4;
    /// Multileaf merkle proof verification failed
    const EINVALID_MERKLE_PROOF: u64 = 5;

    /// unstable append of second vector into first vector
    public fun destructive_reverse_append<Element: drop>(first: &mut vector<Element>, second: vector<Element>) {
        while (!vector::is_empty(&second)) {
            vector::push_back(first, vector::pop_back(&mut second));
        }
    }

    /// Flatten and concatenate the vectors
    public fun vector_flatten_concat<Element: copy + drop>(lhs: &mut vector<Element>, other: vector<vector<Element>>) {
        let i = 0;
        let length = vector::length(&other);
        while (i < length) {
            let bytes = vector::borrow(&other, i);
            vector::append(lhs, *bytes);
            i = i + 1;
        };
    }

    /// Calculates the power of a base raised to an exponent. The result of `base` raised to the power of `exponent`
    public fun calculate_power(base: u128, exponent: u16): u256 {
        let result: u256 = 1;
        let base: u256 = (base as u256);
        assert!((base | (exponent as u256)) != 0, EUNDEFIND_EXP);
        if (base == 0) { return 0 };
        while (exponent != 0) {
            if ((exponent & 0x1) == 1) { result = result * base; };
            base = base * base;
            exponent = (exponent >> 1);
        };
        result
    }

    /// function that Verify merkle tree proof
    public fun verify_merkle_tree(leaf_hash: vector<u8>, proof: vector<vector<u8>>, root: vector<u8>): bool {
        let i = 0;
        let proof_len = vector::length(&proof);
        while (i < proof_len) {
            let item_proof = *vector::borrow(&proof, i);
            let item_proof_hash = if (compare_vector_greater_than(&leaf_hash, &item_proof) < 2) {
                vector::append(&mut item_proof, leaf_hash);
                sui::hash::keccak256(&item_proof)
            } else {
                vector::append(&mut leaf_hash, item_proof);
                sui::hash::keccak256(&leaf_hash)
            };
            leaf_hash = item_proof_hash;
            i = i + 1;
        };
        leaf_hash == root
    }


    /// Retrieves the next element from a vector at a given position and increments the position.
    fun next_element<T: copy>(pos: &mut u64, data: &vector<T>): T {
        assert!(vector::length(data) > *pos, EINDEX_OUT_OF_BOUNDS);
        let h = *vector::borrow(data, *pos);
        *pos = *pos + 1;
        h
    }

    /// ensure multi proof merkle all lengths are valid
    public fun ensure_multileaf_merkle_proof_lengths<T: drop>(proof: vector<vector<u8>>, flags: vector<bool>, leaves: vector<T>) {
        // it should be (leaves_len + proofs_len == flags_len + 1)
        assert!(
            (vector::length(&leaves) + vector::length(&proof)) == (vector::length(&flags) + 1),
            EINVALID_MERKLE_PROOF
        );
    }

    /// Function that verify Multileaf merkle proof
    public fun is_valid_multileaf_merkle_proof(
        proof: vector<vector<u8>>,
        flags: vector<bool>,
        leaves: vector<vector<u8>>,
        root: vector<u8>
    ): bool {
        ensure_multileaf_merkle_proof_lengths(proof, flags, leaves);

        let leaf_pos = 0;
        let hash_pos = 0;
        let proof_pos = 0;
        let hashes = vector[];

        let leave_len = vector::length(&leaves);
        let i = 0;
        while (i < vector::length(&flags)) {
            let flag = *vector::borrow(&flags, i);
            let a = if (leaf_pos < leave_len) {
                next_element(&mut leaf_pos, &leaves)
            } else {
                next_element(&mut hash_pos, &hashes)
            };

            let b = if (flag) {
                if (leaf_pos < leave_len) {
                    next_element(&mut leaf_pos, &leaves)
                } else {
                    next_element(&mut hash_pos, &hashes)
                }
            } else {
                next_element(&mut proof_pos, &proof)
            };

            let hash_pair = if (compare_vector_greater_than(&a, &b) == 1) {
                vector::append(&mut b, a);
                keccak256(&b)
            } else {
                vector::append(&mut a, b);
                keccak256(&a)
            };

            vector::push_back(&mut hashes, hash_pair);
            i = i + 1;
        };

        let calculated_root = if (vector::length(&flags) > 0) {
            assert!(proof_pos == vector::length(&proof), EINVALID_MERKLE_PROOF);
            vector::pop_back(&mut hashes)
        } else if (leave_len > 0) {
            *vector::borrow(&leaves, 0)
        } else {
            *vector::borrow(&proof, 0)
        };
        root == calculated_root
    }

    /// Compate two vector and which of this is greater than, [bytes1 = bytes2] => 0, [bytes1 > bytes2] => 1, [bytes2 < bytes1] => 2
    public fun compare_vector_greater_than(bytes1: &vector<u8>, bytes2: &vector<u8>): u8 {
        assert!(vector::length(bytes1) != 0, EEMPTY_BYTES);
        assert!(vector::length(bytes1) == vector::length(bytes2), EINVALID_BYTES_LENGTH);
        let i = 0;
        let length = vector::length(bytes1);
        let _status = 0; // default value is 0
        loop {
            let a = *vector::borrow(bytes1, i);
            let b = *vector::borrow(bytes2, i);
            if (a > b) {
                _status = 1;
                break
            } else if (a < b) {
                _status = 2;
                break
            };
            i = i + 1;
            if (i >= length) { break }; // break the loop
        };
        _status
    }

    /// Trim a vector to a smaller size, returning the evicted elements in order
    /// There is no `trim` method in the vector for sui, so we have created it here
    public fun trim<Element>(v: &mut vector<Element>, new_len: u64): vector<Element> {
        let res = trim_reverse(v, new_len);
        vector::reverse(&mut res);
        res
    }

    /// Trim a vector to a smaller size, returning the evicted elements in reverse order
    /// There is no `trim_reverse` method in the vector for sui, so we have created it here
    public fun trim_reverse<Element>(v: &mut vector<Element>, new_len: u64): vector<Element> {
        let len = vector::length(v);
        assert!(new_len <= len, EINDEX_OUT_OF_BOUNDS);
        let result = vector::empty();
        while (new_len < len) {
            vector::push_back(&mut result, vector::pop_back(v));
            len = len - 1;
        };
        result
    }

    /// Destroy a vector, just a wrapper around for_each_reverse with a descriptive name
    /// when used in the context of destroying a vector.
    /// There is no `destroy` method in the vector for sui, so we have created it here
    public fun destroy<Element: drop>(v: vector<Element>) {
        let len = vector::length(&v);
        while (len > 0) {
            vector::pop_back(&mut v);
            len = len - 1;
        };
        vector::destroy_empty(v);
    }

    #[test]
    fun test_calculate_power() {
        assert!(calculate_power(1, 0) == 1, 0);
        assert!(calculate_power(0, 1) == 0, 0);
        assert!(calculate_power(2, 7) == 128, 0);
        assert!(calculate_power(2, 8) == 256, 0);
        assert!(calculate_power(12, 0) == 1, 1);
        assert!(calculate_power(15, 3) == 3375, 2);
        assert!(calculate_power(10, 2) == 100, 3);
    }

    #[test]
    #[expected_failure(abort_code = EUNDEFIND_EXP, location = Self)]
    fun test_failure_undefined_exp() {
        assert!(calculate_power(0, 0) == 0, 100);
    }

    #[test]
    fun test_base_with_big_number() {
        assert!(calculate_power(4294967295, 2) == 18446744065119617025, 101);
        assert!(calculate_power(4294967296, 2) == 18446744073709551616, 102);
        assert!(calculate_power(4294967296, 3) == 79228162514264337593543950336, 103);
        assert!(calculate_power(4294967297, 2) == 18446744082299486209, 104);
        assert!(calculate_power(4294967297, 3) == 79228162569604569827557507073, 105);
    }

    #[test]
    #[expected_failure(abort_code = EEMPTY_BYTES)]
    public fun test_compare_vector_two_empty_bytes() {
        let bytes1 = vector::empty<u8>();
        let bytes2 = vector::empty<u8>();
        let result = compare_vector_greater_than(&bytes1, &bytes2);
        assert!(result == 0, 0);
    }
}
