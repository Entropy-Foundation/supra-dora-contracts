module supra_utils::enumerable_set_ring {
    use std::vector;
    use sui::table;
    use sui::tx_context::TxContext;

    /// Key is already exist in the list
    const EKEY_ALREADY_EXIST: u64 = 0;
    /// Pair is argument is empty
    const EINVALID_ARGUMENT_PAIR: u64 = 1;
    /// Values length is out of capacity range
    const EINVALID_VALUES_LENGTH: u64 = 2;

    /// Structure for a Enumerable Set
    struct EnnumerableSetRing<T: copy + drop + store> has store {
        list: vector<T>,
        map: table::Table<T, u64>,
        pointer: u64,
        capacity: u64
    }

    /// Create a new Enumerable Set
    public fun new<T: copy + drop + store>(capacity: u64, ctx: &mut TxContext): EnnumerableSetRing<T> {
        return EnnumerableSetRing<T> { list: vector::empty<T>(), map: table::new<T, u64>(ctx), pointer: 0, capacity }
    }

    /// Add Single value from the Enumerable Set
    public fun add<T: copy + drop + store>(set: &mut EnnumerableSetRing<T>, value: T) {
        assert!(!contains(set, value), EKEY_ALREADY_EXIST);
        if (vector::length(&set.list) == set.capacity) {
            let current_stale_value = vector::borrow_mut(&mut set.list, set.pointer);
            table::remove(&mut set.map, *current_stale_value);
            *current_stale_value = value;
        } else {
            vector::push_back(&mut set.list, value);
        };
        table::add(&mut set.map, value, set.pointer);
        set.pointer = (set.pointer + 1) % set.capacity;
    }

    /// Add Multiple values in the Enumerable Set
    public fun add_all<T: copy + drop + store>(set: &mut EnnumerableSetRing<T>, values: vector<T>) {
        assert!(!vector::is_empty(&values), EINVALID_ARGUMENT_PAIR);
        assert!(vector::length(&values) <= set.capacity, EINVALID_VALUES_LENGTH);
        while (!vector::is_empty(&values)) {
            let value = vector::pop_back(&mut values);
            add(set, value);
        }
    }

    /// Check value contains or not
    public fun contains<T : copy + drop + store>(set: & EnnumerableSetRing<T>, value: T): bool {
        table::contains(&set.map, value)
    }

    /// Clear all the value from the list
    public fun destroy<T: copy + drop + store>(set: &mut EnnumerableSetRing<T>) {
        while (!vector::is_empty(&set.list)) {
            let value = vector::pop_back(&mut set.list);
            table::remove(&mut set.map, value);
        };
        set.pointer = 0;
    }

    /// List all the values
    public fun list<T: copy + drop + store>(set: &EnnumerableSetRing<T>): vector<T> {
        return set.list
    }

    /// Return current length of the EnnumerableSetRing
    public fun length<T: copy + drop + store>(set: &EnnumerableSetRing<T>): u64 {
        return vector::length(&set.list)
    }

    #[test_only]
    struct EnnumerableSetRingTest<T: copy + drop + store> has key {
        id: sui::object::UID,
        e: EnnumerableSetRing<T>
    }

    #[test]
    fun test_values_below_capacity() {
        use sui::test_scenario;
        let admin = @0x1;
        let capacity = 5;

        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        let key1 = vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 0];
        let key2 = vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 1];
        test_scenario::next_tx(scenario, admin);
        {
            let enumerable_data = new<vector<u8>>(capacity, test_scenario::ctx(scenario));
            add(&mut enumerable_data, key1);
            add(&mut enumerable_data, key2);

            assert!(contains(&enumerable_data, key1), 1);
            assert!(contains(&enumerable_data, key2), 2);
            assert!(vector::length(&enumerable_data.list) == 2, 3);
            assert!(enumerable_data.pointer == 2, 4);

            sui::transfer::share_object(
                EnnumerableSetRingTest { id: sui::object::new(test_scenario::ctx(scenario)), e: enumerable_data }
            );
        };
        test_scenario::end(scenario_val);
    }

    #[test]
    fun test_values_higher_than_capacity_and_destroy() {
        use sui::test_scenario;
        let admin = @0x1;
        let capacity = 5;

        let scenario_val = test_scenario::begin(admin);
        let scenario = &mut scenario_val;

        let keys = vector[
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 0],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 1],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 2],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 3],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 4],
        ];
        let keys2 = vector[
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 5],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 6],
            vector[69, 21, 83, 205, 51, 66, 2, 237, 102, 75, 206, 0, 14, 40, 80, 210, 129, 39, 64, 190, 65, 60, 139, 187, 90, 140, 247, 0, 116, 105, 170, 7],
        ];

        test_scenario::next_tx(scenario, admin);
        {
            let enumerable_data = new<vector<u8>>(capacity, test_scenario::ctx(scenario));
            add_all(&mut enumerable_data, keys);
            assert!(length(&enumerable_data) == 5, 2);
            assert!(enumerable_data.pointer == 0, 3);

            add_all(&mut enumerable_data, keys2);
            assert!(length(&enumerable_data) == 5, 4);
            assert!(enumerable_data.pointer == 3, 5);

            destroy(&mut enumerable_data);
            assert!(length(&enumerable_data) == 0, 4);
            assert!(enumerable_data.pointer == 0, 5);

            sui::transfer::share_object(
                EnnumerableSetRingTest { id: sui::object::new(test_scenario::ctx(scenario)), e: enumerable_data }
            );
        };
        test_scenario::end(scenario_val);
    }
}
