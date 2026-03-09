"""Tests for DTXFragmenter: assembly, fragmentation, zero-copy, and edge cases."""

from __future__ import annotations

import itertools

import pytest

from pymobiledevice3.dtx.exceptions import DTXProtocolError
from pymobiledevice3.dtx.fragment import DTXFragment
from pymobiledevice3.dtx.fragmenter import MAX_FRAGMENT_SIZE, MAX_MESSAGE_SIZE, DTXFragmenter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _first_frag(total_size: int, count: int = 2, identifier: int = 1) -> DTXFragment:
    """Build a first (header-only) fragment declaring *total_size* bytes."""
    return DTXFragment(
        index=0,
        count=count,
        data_size=total_size,
        identifier=identifier,
    )


def _body_frag(index: int, payload: bytes | bytearray, count: int = 2, identifier: int = 1) -> DTXFragment:
    """Build a non-first body fragment carrying *payload*."""
    return DTXFragment(
        index=index,
        count=count,
        data_size=len(payload),
        identifier=identifier,
        payload=memoryview(bytearray(payload)),
    )


async def _collect(gen) -> list[DTXFragment]:
    """Drain an async generator of DTXFragments into a list."""
    return [f async for f in gen]


# ---------------------------------------------------------------------------
# DTXFragmenter - construction
# ---------------------------------------------------------------------------


class TestDTXFragmenterConstruction:
    def test_basic(self):
        first = _first_frag(total_size=100, count=3)
        fragmenter = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        assert fragmenter.identifier == 1
        assert fragmenter.declared_size == 100

    def test_zero_data_size_raises(self):
        first = _first_frag(total_size=0, count=2)
        with pytest.raises(DTXProtocolError, match="data_size=0"):
            DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)

    def test_exceeds_max_message_size_raises(self):
        first = _first_frag(total_size=MAX_MESSAGE_SIZE + 1, count=2)
        with pytest.raises(DTXProtocolError, match="MAX_MESSAGE_SIZE"):
            DTXFragmenter(first, current_buffered=0, max_buffered_size=MAX_MESSAGE_SIZE * 2)

    def test_exceeds_max_buffered_size_raises(self):
        first = _first_frag(total_size=500, count=2)
        with pytest.raises(DTXProtocolError, match="MAX_BUFFERED_SIZE"):
            DTXFragmenter(first, current_buffered=600, max_buffered_size=1000)

    def test_exactly_at_max_buffered_size_is_ok(self):
        first = _first_frag(total_size=400, count=2)
        # current_buffered + total == max_buffered_size → accepted
        fragmenter = DTXFragmenter(first, current_buffered=600, max_buffered_size=1000)
        assert fragmenter.declared_size == 400

    def test_exactly_at_max_message_size_is_ok(self):
        first = _first_frag(total_size=MAX_MESSAGE_SIZE, count=2)
        fragmenter = DTXFragmenter(first, current_buffered=0, max_buffered_size=MAX_MESSAGE_SIZE)
        assert fragmenter.declared_size == MAX_MESSAGE_SIZE


# ---------------------------------------------------------------------------
# DTXFragmenter - add() / assemble() - in-order (zero-copy path)
# ---------------------------------------------------------------------------


class TestDTXFragmenterInOrder:
    def test_two_fragments_in_order(self):
        body = b"hello world"
        first = _first_frag(total_size=len(body), count=2)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        internal_buffer = f._buffer  # keep reference to verify zero-copy

        done = f.add(_body_frag(index=1, payload=body))
        assert done is True

        result, meta = f.assemble()
        assert bytes(result) == body
        assert meta is first

        # Zero-copy: in-order fragments must return the pre-allocated buffer,
        # not a new allocation.
        assert result is internal_buffer

    def test_three_fragments_in_order(self):
        part_a = b"AAAA"
        part_b = b"BBBB"
        first = _first_frag(total_size=len(part_a) + len(part_b), count=3)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        internal_buffer = f._buffer

        assert f.add(_body_frag(index=1, payload=part_a, count=3)) is False
        assert f.add(_body_frag(index=2, payload=part_b, count=3)) is True

        result, _ = f.assemble()
        assert bytes(result) == part_a + part_b
        assert result is internal_buffer

    def test_add_returns_false_until_last(self):
        parts = [bytes([i] * 10) for i in range(1, 5)]
        total = sum(len(p) for p in parts)
        first = _first_frag(total_size=total, count=len(parts) + 1)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=total + 100)

        for i, part in enumerate(parts, start=1):
            is_last = i == len(parts)
            assert f.add(_body_frag(index=i, payload=part, count=len(parts) + 1)) is is_last

        result, _ = f.assemble()
        assert bytes(result) == b"".join(parts)


# ---------------------------------------------------------------------------
# DTXFragmenter - assemble() - out-of-order (copy path)
# ---------------------------------------------------------------------------


class TestDTXFragmenterOutOfOrder:
    def test_two_fragments_reversed(self):
        part_a = b"FIRST_PART_"
        part_b = b"SECOND_PART"
        first = _first_frag(total_size=len(part_a) + len(part_b), count=3)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        original_buffer = f._buffer

        # Arrive in reverse order: index 2 before index 1
        assert f.add(_body_frag(index=2, payload=part_b, count=3)) is False
        assert f.add(_body_frag(index=1, payload=part_a, count=3)) is True

        result, _ = f.assemble()
        assert bytes(result) == part_a + part_b

        # Out-of-order must produce a NEW buffer (the original was written
        # in arrival order, so its bytes are scrambled).
        assert result is not original_buffer

    def test_three_fragments_permutation(self):
        """Every non-identity permutation of 3 body fragments."""
        parts = [bytes([i] * 8) for i in range(1, 4)]
        expected = b"".join(parts)
        total = len(expected)

        for perm in itertools.permutations([1, 2, 3]):
            if perm == (1, 2, 3):
                continue  # in-order covered elsewhere
            first = _first_frag(total_size=total, count=4)
            f = DTXFragmenter(first, current_buffered=0, max_buffered_size=total + 100)
            for idx in perm:
                f.add(_body_frag(index=idx, payload=parts[idx - 1], count=4))
            result, _ = f.assemble()
            assert bytes(result) == expected, f"Failed for permutation {perm}"


# ---------------------------------------------------------------------------
# DTXFragmenter - add() error cases
# ---------------------------------------------------------------------------


class TestDTXFragmenterErrors:
    def test_duplicate_fragment_index_raises(self):
        first = _first_frag(total_size=20, count=3)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        f.add(_body_frag(index=1, payload=b"A" * 10, count=3))
        with pytest.raises(DTXProtocolError, match=r"[Dd]uplicate"):
            f.add(_body_frag(index=1, payload=b"B" * 5, count=3))

    def test_overflow_raises(self):
        """A fragment whose payload would push the write pointer past declared_size."""
        first = _first_frag(total_size=10, count=2)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        with pytest.raises(DTXProtocolError, match="exceed"):
            f.add(_body_frag(index=1, payload=b"X" * 11, count=2))

    def test_partial_overflow_raises(self):
        """First fragment OK, second pushes past the boundary."""
        first = _first_frag(total_size=10, count=3)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        f.add(_body_frag(index=1, payload=b"A" * 6, count=3))
        with pytest.raises(DTXProtocolError, match="exceed"):
            f.add(_body_frag(index=2, payload=b"B" * 5, count=3))  # 6+5=11 > 10

    def test_assemble_before_all_fragments_raises(self):
        first = _first_frag(total_size=20, count=3)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        f.add(_body_frag(index=1, payload=b"A" * 10, count=3))
        with pytest.raises(AssertionError):
            f.assemble()

    def test_none_payload_raises(self):
        first = _first_frag(total_size=10, count=2)
        f = DTXFragmenter(first, current_buffered=0, max_buffered_size=1024)
        frag = DTXFragment(index=1, count=2, data_size=10, identifier=1, payload=None)
        with pytest.raises(DTXProtocolError):
            f.add(frag)


# ---------------------------------------------------------------------------
# DTXFragmenter.fragment() - single-fragment path
# ---------------------------------------------------------------------------


class TestFragmentSingleFragment:
    async def test_empty_payload(self):
        frags = await _collect(DTXFragmenter.fragment(memoryview(b"")))
        assert len(frags) == 1
        assert frags[0].index == 0
        assert frags[0].count == 1
        assert frags[0].data_size == 0
        assert len(frags[0].payload) == 0

    async def test_single_chunk_zero_copy(self):
        """Single memoryview ≤ MAX_FRAGMENT_SIZE → payload IS the same buffer."""
        src = bytearray(b"the quick brown fox")
        mv = memoryview(src)
        frags = await _collect(DTXFragmenter.fragment(mv))
        assert len(frags) == 1
        frag = frags[0]
        assert frag.index == 0
        assert frag.count == 1
        assert bytes(frag.payload) == bytes(src)
        # The payload must share the same backing bytearray (zero-copy).
        assert frag.payload.obj is src

    async def test_multiple_chunks_fit_in_one_fragment(self):
        """Multiple memoryviews whose total is ≤ MAX_FRAGMENT_SIZE → concatenated once."""
        a = bytearray(b"hello ")
        b_ = bytearray(b"world")
        frags = await _collect(DTXFragmenter.fragment(memoryview(a), memoryview(b_)))
        assert len(frags) == 1
        assert bytes(frags[0].payload) == b"hello world"

    async def test_exactly_max_fragment_size(self):
        src = bytearray(MAX_FRAGMENT_SIZE)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))
        assert len(frags) == 1
        assert frags[0].data_size == MAX_FRAGMENT_SIZE
        assert frags[0].payload.obj is src


# ---------------------------------------------------------------------------
# DTXFragmenter.fragment() - multi-fragment path
# ---------------------------------------------------------------------------


class TestFragmentMultiFragment:
    async def test_two_fragments_exact_split(self):
        """Payload is exactly 2 * MAX_FRAGMENT_SIZE."""
        total = MAX_FRAGMENT_SIZE * 2
        src = bytearray(list(range(256)) * (total // 256))
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))

        # header-only + 2 body fragments
        assert len(frags) == 3
        assert frags[0].index == 0
        assert frags[0].count == 3
        assert frags[0].data_size == total
        assert len(frags[0].payload) == 0

        assert frags[1].index == 1
        assert frags[1].data_size == MAX_FRAGMENT_SIZE
        assert frags[2].index == 2
        assert frags[2].data_size == MAX_FRAGMENT_SIZE

        # Reassemble and verify
        assembled = bytes(frags[1].payload) + bytes(frags[2].payload)
        assert assembled == bytes(src)

    async def test_three_fragments_partial_last(self):
        """Payload is 2.5 * MAX_FRAGMENT_SIZE → 3 body fragments, last partial."""
        total = int(MAX_FRAGMENT_SIZE * 2.5)
        src = bytearray(b"\xab" * total)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))

        # header-only + 3 body fragments
        assert len(frags) == 4
        body_frags = frags[1:]
        assembled = b"".join(bytes(f.payload) for f in body_frags)
        assert assembled == bytes(src)

    async def test_large_payload_roundtrip(self):
        """Fragment then reassemble a large payload through DTXFragmenter."""
        total = MAX_FRAGMENT_SIZE * 3 + 12345
        src = bytearray(i % 251 for i in range(total))
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))

        body_frags = frags[1:]
        first = frags[0]

        assembler = DTXFragmenter(
            first,
            current_buffered=0,
            max_buffered_size=MAX_MESSAGE_SIZE,
        )
        for frag in body_frags:
            done = assembler.add(frag)

        assert done is True
        result, _ = assembler.assemble()
        assert bytes(result) == bytes(src)

    async def test_zero_copy_body_fragments_single_source(self):
        """Each body fragment from a single large source chunk must be a sub-view."""
        total = MAX_FRAGMENT_SIZE * 2 + 1000
        src = bytearray(b"\xcc" * total)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))

        body_frags = frags[1:]
        for frag in body_frags:
            # Every body fragment must share the same backing bytearray as src.
            assert frag.payload.obj is src, (
                f"Fragment {frag.index} payload not zero-copy: payload.obj={id(frag.payload.obj):#x}, src={id(src):#x}"
            )

    async def test_boundary_fragment_allocates_new_buffer(self):
        """When a fragment straddles a source-chunk boundary, a new bytearray is allocated."""
        # Split the source into two half-sized chunks so the first body
        # fragment boundary falls exactly at the chunk boundary — BUT then
        # use unequal splits to force a boundary-crossing fragment.
        half = MAX_FRAGMENT_SIZE // 2
        chunk_a = bytearray(b"\xaa" * (half + 1))  # slightly over half
        chunk_b = bytearray(b"\xbb" * (MAX_FRAGMENT_SIZE - 1))  # fills the rest of the second body frag

        frags = await _collect(DTXFragmenter.fragment(memoryview(chunk_a), memoryview(chunk_b)))
        assert len(frags) == 3  # header + 2 body

        body_frags = frags[1:]
        assembled = b"".join(bytes(f.payload) for f in body_frags)
        assert assembled == bytes(chunk_a) + bytes(chunk_b)

        # At least one body fragment must NOT share obj with either source chunk
        # (the one that crossed the chunk boundary gets its own allocation).
        boundary_frag = body_frags[0]  # the first body fragment straddles the split
        assert boundary_frag.payload.obj is not chunk_a
        assert boundary_frag.payload.obj is not chunk_b

    async def test_exceeds_max_message_size_raises(self):
        oversized = bytearray(MAX_MESSAGE_SIZE + 1)
        with pytest.raises(DTXProtocolError, match="MAX_MESSAGE_SIZE"):
            await _collect(DTXFragmenter.fragment(memoryview(oversized)))

    async def test_roundtrip_out_of_order_assembly(self):
        """Fragment a payload, then feed body fragments to assembler in reverse order."""
        total = MAX_FRAGMENT_SIZE * 2 + 7777
        src = bytearray(i % 199 for i in range(total))
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))

        first_frag = frags[0]
        body_frags = frags[1:]  # original order: index 1, 2, 3...

        assembler = DTXFragmenter(
            first_frag,
            current_buffered=0,
            max_buffered_size=MAX_MESSAGE_SIZE,
        )

        # Feed in reverse order.
        for frag in reversed(body_frags):
            done = assembler.add(frag)

        assert done is True
        result, _ = assembler.assemble()
        assert bytes(result) == bytes(src)


# ---------------------------------------------------------------------------
# DTXFragmenter.fragment() - multiple source chunks, multi-fragment
# ---------------------------------------------------------------------------


class TestFragmentMultipleSourceChunks:
    async def test_many_small_chunks(self):
        """Many small chunks (each 1 byte) spanning multiple fragments."""
        chunk_count = MAX_FRAGMENT_SIZE * 2 + 500
        chunks = [memoryview(bytearray([i % 256])) for i in range(chunk_count)]
        frags = await _collect(DTXFragmenter.fragment(*chunks))

        body_frags = frags[1:]
        assembled = b"".join(bytes(f.payload) for f in body_frags)
        assert len(assembled) == chunk_count
        assert assembled == bytes(i % 256 for i in range(chunk_count))

    async def test_two_chunks_same_size_as_one_fragment(self):
        """Two chunks each of half MAX_FRAGMENT_SIZE → exactly one body fragment."""
        half = MAX_FRAGMENT_SIZE // 2
        a = bytearray(b"\x01" * half)
        b_ = bytearray(b"\x02" * half)
        frags = await _collect(DTXFragmenter.fragment(memoryview(a), memoryview(b_)))
        # total == MAX_FRAGMENT_SIZE → single fragment (no multi-fragment path)
        assert len(frags) == 1
        assert bytes(frags[0].payload) == bytes(a) + bytes(b_)

    async def test_index_sequence_is_contiguous(self):
        """Fragment indices must be 0, 1, 2, … for any payload size."""
        total = MAX_FRAGMENT_SIZE * 4 + 3
        src = bytearray(total)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))
        for expected_idx, frag in enumerate(frags):
            assert frag.index == expected_idx

    async def test_count_is_consistent(self):
        """All fragments in a batch must carry the same count value."""
        total = MAX_FRAGMENT_SIZE * 3 + 1
        src = bytearray(total)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))
        counts = {f.count for f in frags}
        assert len(counts) == 1
        assert frags[0].count == len(frags)

    async def test_total_body_size_matches_declared(self):
        """Sum of body fragment data_sizes must equal first fragment's data_size."""
        total = MAX_FRAGMENT_SIZE * 2 + 987
        src = bytearray(total)
        frags = await _collect(DTXFragmenter.fragment(memoryview(src)))
        declared = frags[0].data_size
        body_total = sum(f.data_size for f in frags[1:])
        assert body_total == declared
        assert declared == total
