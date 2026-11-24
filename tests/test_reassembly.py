import pytest

from frag import (
    add_fragment,
    assemble,
    coverage,
    expire,
    is_complete,
    offset_bytes,
    parse_fragment,
    reassembly_batch,
)


def packet(identifier, offset, mf, payload, arrived=0.0):
    return {
        "id": identifier,
        "offset": offset,
        "mf": mf,
        "payload": payload,
        "arrived": arrived,
    }


def record(start, payload, arrived=0.0, mf=False):
    return {
        "start": start,
        "end": start + len(payload),
        "payload": payload,
        "offset": start // 8,
        "mf": mf,
        "length": len(payload),
        "arrived": arrived,
    }


def state_with(fragments, total_length, last_fragment_seen=True):
    return {
        "id": 1,
        "fragments": fragments,
        "last_fragment_seen": last_fragment_seen,
        "total_length": total_length,
        "max_bytes": 4096,
        "max_fragments": 64,
        "last_update": 0.0,
    }


def build(packets):
    state = {}
    for item in packets:
        add_fragment(state, item, "drop")
    return state


def individual_reassembly(packets):
    states = {}
    for item in packets:
        fragment = parse_fragment(item)
        state = states.setdefault(fragment["id"], {})
        add_fragment(state, fragment, "drop")
    return {identifier: assemble(state) for identifier, state in states.items()}


def test_offset_bytes_uses_eight_byte_units():
    assert offset_bytes({"offset": 3}) == 24


def test_partial_overlap_is_detected():
    state = {}
    add_fragment(state, packet(1, 0, False, b"A" * 16, 0.0), "drop")
    add_fragment(state, packet(1, 1, False, b"B" * 16, 1.0), "drop")
    assert len(state["fragments"]) == 1
    assert coverage(state) == [[0, 16]]


def test_overlap_drops_new_fragment_not_overwrite():
    state = {}
    add_fragment(state, packet(2, 0, False, b"A" * 8, 0.0), "drop")
    add_fragment(state, packet(2, 0, False, b"B" * 8, 1.0), "drop")
    assert assemble(state) == b"A" * 8


def test_coverage_merges_intersecting_intervals():
    state = state_with(
        [
            record(0, b"A" * 16, 0.0, True),
            record(8, b"B" * 16, 1.0, False),
        ],
        24,
    )
    assert coverage(state) == [[0, 24]]


def test_completeness_requires_no_internal_gap():
    state = {}
    add_fragment(state, packet(3, 0, True, b"A" * 8, 0.0), "drop")
    add_fragment(state, packet(3, 2, False, b"C" * 8, 1.0), "drop")
    assert is_complete(state) is False


def test_assemble_orders_by_offset_not_arrival():
    state = state_with(
        [
            record(8, b"B" * 8, 0.0, False),
            record(0, b"A" * 8, 1.0, True),
        ],
        16,
    )
    assert assemble(state) == b"A" * 8 + b"B" * 8


def test_assemble_raises_on_missing_fragment():
    state = {}
    add_fragment(state, packet(4, 0, True, b"A" * 8, 0.0), "drop")
    with pytest.raises(ValueError):
        assemble(state)


def test_expire_does_not_reset_age_on_cleanup():
    state = state_with([record(0, b"A" * 8, 0.0, False)], 8)
    removed = 0
    removed += expire(state, 4.0, 5.0)
    removed += expire(state, 8.0, 5.0)
    removed += expire(state, 12.0, 5.0)
    assert removed == 1


def test_memory_budget_counts_total_bytes():
    state = {
        "id": 5,
        "fragments": [],
        "last_fragment_seen": False,
        "total_length": None,
        "max_bytes": 24,
        "max_fragments": 64,
        "last_update": 0.0,
    }
    for index in range(3):
        add_fragment(
            state,
            packet(5, index * 2, index < 2, b"X" * 16, float(index)),
            "drop",
        )
    used = sum(len(fragment["payload"]) for fragment in state["fragments"])
    assert used <= state["max_bytes"]


def test_batch_keeps_identifiers_isolated():
    packets = [
        packet(11, 0, True, b"A" * 8, 0.0),
        packet(11, 1, False, b"B" * 8, 1.0),
        packet(22, 0, True, b"C" * 8, 2.0),
        packet(22, 1, False, b"D" * 8, 3.0),
    ]
    result = reassembly_batch(packets, "drop", 10.0)
    assert result[11] == b"A" * 8 + b"B" * 8
    assert result[22] == b"C" * 8 + b"D" * 8


def test_two_fragments_in_order_reassemble_exactly():
    state = {}
    add_fragment(state, packet(31, 0, True, b"A" * 8, 0.0), "drop")
    add_fragment(state, packet(31, 1, False, b"B" * 8, 1.0), "drop")
    assert assemble(state) == b"A" * 8 + b"B" * 8


def test_out_of_order_matches_in_order():
    in_order = build(
        [
            packet(32, 0, True, b"A" * 8, 0.0),
            packet(32, 1, False, b"B" * 8, 1.0),
        ]
    )
    reversed_order = build(
        [
            packet(32, 1, False, b"B" * 8, 0.0),
            packet(32, 0, True, b"A" * 8, 1.0),
        ]
    )
    assert assemble(in_order) == assemble(reversed_order)


def test_overlapping_fragment_rejected():
    state = {}
    add_fragment(state, packet(33, 0, False, b"A" * 16, 0.0), "drop")
    add_fragment(state, packet(33, 1, False, b"B" * 16, 1.0), "drop")
    assert assemble(state) == b"A" * 16


def test_missing_fragment_raises():
    state = {}
    add_fragment(state, packet(34, 0, True, b"A" * 8, 0.0), "drop")
    add_fragment(state, packet(34, 2, False, b"C" * 8, 1.0), "drop")
    with pytest.raises(ValueError):
        assemble(state)


def test_two_batches_match_individual_reassembly():
    packets_a = [
        packet(41, 0, True, b"A" * 8, 0.0),
        packet(41, 1, False, b"B" * 8, 1.0),
        packet(42, 0, True, b"C" * 8, 2.0),
        packet(42, 1, False, b"D" * 8, 3.0),
    ]
    packets_b = [
        packet(51, 0, True, b"E" * 8, 0.0),
        packet(51, 1, False, b"F" * 8, 1.0),
        packet(52, 0, True, b"G" * 8, 2.0),
        packet(52, 1, False, b"H" * 8, 3.0),
    ]
    assert reassembly_batch(packets_a, "drop", 30.0) == individual_reassembly(packets_a)
    assert reassembly_batch(packets_b, "drop", 30.0) == individual_reassembly(packets_b)