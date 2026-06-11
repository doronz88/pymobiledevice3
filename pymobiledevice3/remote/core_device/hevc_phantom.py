"""
Phantom HEVC frame generator: clones the captured IDR with a rewritten
slice header so the decoder's DPB has the references the first delta
expects.

**Why this exists.** iOS screen-mirror's HEVC encoder emits the IDR at
POC=0 and then jumps the first real delta to a high POC (we've measured
POC=163 in a 30 s stress capture). Every delta after that references
the immediately preceding 11 POCs (`RPS[N].neg = [(-1,1)(-2,1)(-3,0)…
(-11,0)]`). The decoder rejects the entire delta chain because
POC=152…162 were never emitted by the encoder.

Apple's own decoder (and ffmpeg's permissive path) substitute missing
references silently — but that produces visible tears during motion.
WebCodecs validates RPS strictly and bails on the very first delta.

**Fix.** Cache the IDR's slice. When the first real delta arrives, parse
its POC and synthesise 11 phantom NALs at POC=delta_poc-11 …
delta_poc-1. Each phantom is built from the IDR's *intra* slice body
(same `slice_segment_data`) under a rewritten TRAIL_R slice header so
the decoder treats them as 11 ordinary I-frames at the expected POCs.
The decoder's DPB then has exactly the references the chain expects
and decodes cleanly from the first delta on.

This adds 11x IDR-size (~300 kB) at stream start. Mid-stream POC gaps
do not occur in practice (verified: 1 jump in 874 slices over 30 s of
heavy stress), so no further phantoms are needed.

References:
    ISO/IEC 23008-2 (HEVC bitstream), §7.3.6 slice_segment_header
"""

from typing import Optional


# ---------------------------------------------------------------------------
# Bit I/O — minimal, only what slice-header rewriting needs
# ---------------------------------------------------------------------------
def _deemul(nal: bytes) -> bytes:
    """Remove emulation prevention bytes from the NAL payload past its
    2-byte header."""
    rb = bytearray(nal[:2])
    i = 2
    while i < len(nal):
        if i + 2 < len(nal) and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == 3:
            rb.extend(nal[i : i + 2])
            i += 3
        else:
            rb.append(nal[i])
            i += 1
    return bytes(rb)


def _emul(rbsp: bytes) -> bytes:
    """Re-insert emulation prevention bytes (00 00 0x → 00 00 03 0x for x<=3)."""
    out = bytearray(rbsp[:2])  # NAL header doesn't need EP
    i = 2
    zero_run = 0
    while i < len(rbsp):
        b = rbsp[i]
        if zero_run >= 2 and b <= 0x03:
            out.append(0x03)
            zero_run = 0
        out.append(b)
        if b == 0:
            zero_run += 1
        else:
            zero_run = 0
        i += 1
    return bytes(out)


class _BitReader:
    """Bit-level reader over a deemulated RBSP starting after the NAL header."""

    def __init__(self, data: bytes, start_byte_offset: int = 2) -> None:
        self.d = data
        self.p = start_byte_offset * 8

    def b(self, n: int) -> int:
        v = 0
        for _ in range(n):
            v = (v << 1) | ((self.d[self.p >> 3] >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v

    def ue(self) -> int:
        z = 0
        while self.b(1) == 0 and z < 32:
            z += 1
        if z == 0:
            return 0
        return (1 << z) - 1 + (self.b(z) if z > 0 else 0)

    def se(self) -> int:
        v = self.ue()
        return -(v >> 1) if (v & 1) == 0 else (v + 1) >> 1


class _BitWriter:
    """Bit-level writer producing an RBSP. Starts already containing the
    caller-supplied 2-byte NAL header."""

    def __init__(self, nal_header: bytes) -> None:
        assert len(nal_header) == 2
        self.buf = bytearray(nal_header)
        self.byte = 0
        self.nbits = 0

    def b(self, n: int, value: int) -> None:
        for i in range(n - 1, -1, -1):
            bit = (value >> i) & 1
            self.byte = (self.byte << 1) | bit
            self.nbits += 1
            if self.nbits == 8:
                self.buf.append(self.byte)
                self.byte = 0
                self.nbits = 0

    def ue(self, value: int) -> None:
        # Compute number of leading zeros (code length = 2k+1 bits)
        v = value + 1
        nbits = v.bit_length()
        self.b(nbits - 1, 0)
        self.b(nbits, v)

    def se(self, value: int) -> None:
        if value <= 0:
            self.ue(-2 * value)
        else:
            self.ue(2 * value - 1)

    def byte_align(self) -> None:
        # RBSP byte alignment: a 1 bit then zeros until byte boundary.
        self.b(1, 1)
        while self.nbits != 0:
            self.b(1, 0)

    def bytes(self) -> bytes:
        # Flush any trailing partial byte by padding with zeros (caller is
        # expected to byte_align first; we just safeguard here).
        if self.nbits != 0:
            self.byte <<= 8 - self.nbits
            self.buf.append(self.byte)
            self.byte = 0
            self.nbits = 0
        return bytes(self.buf)


# ---------------------------------------------------------------------------
# SPS / PPS parser — only the fields slice_segment_header() depends on
# ---------------------------------------------------------------------------
def _parse_sps(sps_nal: bytes) -> dict:
    deemul = _deemul(sps_nal)
    r = _BitReader(deemul)
    r.b(4)  # sps_video_parameter_set_id
    max_sub = r.b(3)
    r.b(1)  # temporal_id_nesting
    # profile_tier_level
    r.b(2)
    r.b(1)
    r.b(5)
    r.b(32)
    r.b(48)
    r.b(8)
    sub_present, level_present = [], []
    for _ in range(max_sub):
        sub_present.append(r.b(1))
        level_present.append(r.b(1))
    if max_sub > 0:
        for _ in range(max_sub, 8):
            r.b(2)
    for i in range(max_sub):
        if sub_present[i]:
            r.b(2)
            r.b(1)
            r.b(5)
            r.b(32)
            r.b(48)
        if level_present[i]:
            r.b(8)
    r.ue()  # sps_seq_parameter_set_id
    chroma_format_idc = r.ue()
    if chroma_format_idc == 3:
        r.b(1)
    r.ue()
    r.ue()  # width, height
    if r.b(1):  # conformance window
        r.ue()
        r.ue()
        r.ue()
        r.ue()
    r.ue()
    r.ue()  # bit_depth_luma/chroma minus 8
    log2_max_poc_lsb = r.ue() + 4
    spsslo_present = r.b(1)
    for _ in range(max_sub + 1 if not spsslo_present else 1):
        r.ue()
        r.ue()
        r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    if r.b(1):  # scaling list
        raise NotImplementedError("scaling list parsing not handled")
    r.b(1)  # amp
    sample_adaptive_offset_enabled = r.b(1)
    pcm = r.b(1)
    if pcm:
        r.b(4)
        r.b(4)
        r.ue()
        r.ue()
        r.b(1)
    num_st_rps = r.ue()
    # Skip past all RPS entries (we don't need their content here, just to
    # advance the bit pointer to long_term_ref_pics_present_flag).
    rps_offsets = []
    for idx in range(num_st_rps):
        inter_pred = 0 if idx == 0 else r.b(1)
        if inter_pred:
            delta_idx_m1 = 0 if idx == num_st_rps else r.ue()
            ref_idx = idx - (delta_idx_m1 + 1)
            r.b(1)  # delta_rps_sign
            r.ue()  # abs_delta_rps_m1
            num_ref = rps_offsets[ref_idx]["num_ref"]
            used_flags = [r.b(1) for _ in range(num_ref + 1)]
            for j in range(num_ref + 1):
                if not used_flags[j]:
                    r.b(1)
            # We can't easily recompute num_ref without full RPS table, but
            # we don't need it — see fallback below.
            rps_offsets.append({"num_ref": num_ref})
        else:
            nn = r.ue()
            np_ = r.ue()
            for _ in range(nn):
                r.ue()
                r.b(1)
            for _ in range(np_):
                r.ue()
                r.b(1)
            rps_offsets.append({"num_ref": nn + np_})
    long_term_ref_pics_present = r.b(1)
    if long_term_ref_pics_present:
        num_long_term_sps = r.ue()
        for _ in range(num_long_term_sps):
            r.b(log2_max_poc_lsb)
            r.b(1)
    else:
        num_long_term_sps = 0
    sps_temporal_mvp_enabled = r.b(1)
    # strong_intra_smoothing follows; we don't need anything below.
    return {
        "chroma_format_idc": chroma_format_idc,
        "log2_max_poc_lsb": log2_max_poc_lsb,
        "num_st_rps": num_st_rps,
        "sample_adaptive_offset_enabled": sample_adaptive_offset_enabled,
        "long_term_ref_pics_present": long_term_ref_pics_present,
        "num_long_term_sps": num_long_term_sps,
        "sps_temporal_mvp_enabled": sps_temporal_mvp_enabled,
    }


def _parse_pps(pps_nal: bytes) -> dict:
    deemul = _deemul(pps_nal)
    r = _BitReader(deemul)
    r.ue()  # pps_id
    r.ue()  # sps_id
    r.b(1)  # dependent_slice_segments_enabled
    output_flag_present = r.b(1)
    num_extra_slice_header_bits = r.b(3)
    r.b(1)  # sign_data_hiding
    cabac_init_present = r.b(1)
    r.ue()
    r.ue()  # default ref idx active
    r.se()  # init_qp_minus26
    r.b(1)  # constrained_intra_pred
    r.b(1)  # transform_skip_enabled
    cu_qp_delta_enabled = r.b(1)
    if cu_qp_delta_enabled:
        r.ue()  # diff_cu_qp_delta_depth
    r.se()
    r.se()  # pps_cb_qp_offset, pps_cr_qp_offset
    pps_slice_chroma_qp_offsets_present = r.b(1)
    r.b(1)  # weighted_pred
    r.b(1)  # weighted_bipred
    r.b(1)  # transquant_bypass_enabled
    tiles_enabled = r.b(1)
    entropy_coding_sync_enabled = r.b(1)
    if tiles_enabled:
        num_tile_cols_m1 = r.ue()
        num_tile_rows_m1 = r.ue()
        uniform_spacing = r.b(1)
        if not uniform_spacing:
            for _ in range(num_tile_cols_m1):
                r.ue()
            for _ in range(num_tile_rows_m1):
                r.ue()
        r.b(1)  # loop_filter_across_tiles_enabled
    pps_loop_filter_across_slices_enabled = r.b(1)
    deblocking_filter_control_present = r.b(1)
    deblocking_filter_override_enabled = 0
    pps_deblocking_filter_disabled = 0
    if deblocking_filter_control_present:
        deblocking_filter_override_enabled = r.b(1)
        pps_deblocking_filter_disabled = r.b(1)
        if not pps_deblocking_filter_disabled:
            r.se()
            r.se()
    pps_scaling_list_data_present = r.b(1)
    if pps_scaling_list_data_present:
        raise NotImplementedError("PPS scaling_list_data not handled")
    r.b(1)  # lists_modification_present
    r.ue()  # log2_parallel_merge_level_minus2
    slice_segment_header_extension_present = r.b(1)
    return {
        "output_flag_present": output_flag_present,
        "num_extra_slice_header_bits": num_extra_slice_header_bits,
        "cabac_init_present": cabac_init_present,
        "pps_slice_chroma_qp_offsets_present": pps_slice_chroma_qp_offsets_present,
        "tiles_enabled": tiles_enabled,
        "entropy_coding_sync_enabled": entropy_coding_sync_enabled,
        "pps_loop_filter_across_slices_enabled": pps_loop_filter_across_slices_enabled,
        "deblocking_filter_override_enabled": deblocking_filter_override_enabled,
        "pps_deblocking_filter_disabled": pps_deblocking_filter_disabled,
        "slice_segment_header_extension_present": slice_segment_header_extension_present,
    }


# ---------------------------------------------------------------------------
# Slice header rewriting — extract IDR slice body, wrap in new TRAIL_R header
# ---------------------------------------------------------------------------
def _read_idr_slice_header(idr_nal: bytes, sps: dict, pps: dict) -> dict:
    """Fully parse the IDR's slice_segment_header() so we know the bit
    offset of slice_segment_data and capture the header values our phantom
    needs to mirror (pps_id, slice_qp_delta)."""
    deemul = _deemul(idr_nal)
    r = _BitReader(deemul)
    nut = (idr_nal[0] >> 1) & 0x3F
    assert nut in (19, 20, 21), f"not an IRAP NAL: {nut}"

    fs = r.b(1)
    assert fs == 1
    no_output = r.b(1)  # IRAP-only field
    pps_id = r.ue()
    for _ in range(pps["num_extra_slice_header_bits"]):
        r.b(1)
    slice_type = r.ue()
    if pps["output_flag_present"]:
        r.b(1)  # pic_output_flag

    # IRAP has no POC and no RPS. IDR_N_LP/IDR_W_RADL also have no
    # slice_temporal_mvp_enabled_flag.
    slice_sao_luma_flag = 0
    slice_sao_chroma_flag = 0
    if sps["sample_adaptive_offset_enabled"]:
        slice_sao_luma_flag = r.b(1)
        if sps["chroma_format_idc"] != 0:
            slice_sao_chroma_flag = r.b(1)

    # I slice: no ref index / weighted pred / mvd parameters.
    slice_qp_delta = r.se()
    if pps["pps_slice_chroma_qp_offsets_present"]:
        r.se()
        r.se()

    deblocking_filter_override_flag = 0
    slice_deblocking_filter_disabled_flag = pps["pps_deblocking_filter_disabled"]
    if pps["deblocking_filter_override_enabled"]:
        deblocking_filter_override_flag = r.b(1)
    if deblocking_filter_override_flag:
        slice_deblocking_filter_disabled_flag = r.b(1)
        if not slice_deblocking_filter_disabled_flag:
            r.se()
            r.se()
    if pps["pps_loop_filter_across_slices_enabled"] and (
        slice_sao_luma_flag or slice_sao_chroma_flag or not slice_deblocking_filter_disabled_flag
    ):
        r.b(1)  # slice_loop_filter_across_slices_enabled_flag

    # PPS sets entropy_coding_sync_enabled=1 (and/or tiles): the slice
    # header carries entry-point offsets for CABAC sub-streams.
    if pps["tiles_enabled"] or pps["entropy_coding_sync_enabled"]:
        n_offsets = r.ue()
        if n_offsets > 0:
            offset_len_m1 = r.ue()
            for _ in range(n_offsets):
                r.b(offset_len_m1 + 1)

    if pps["slice_segment_header_extension_present"]:
        ext_len = r.ue()
        for _ in range(ext_len):
            r.b(8)
    # byte_alignment() = "1" bit + zeros until byte boundary.
    align_bit = r.b(1)
    assert align_bit == 1, "expected byte_alignment trailing 1"
    while r.p & 7:
        zero = r.b(1)
        assert zero == 0, "byte_alignment must be 0-padded"
    body_byte_offset = r.p >> 3

    return {
        "slice_qp_delta": slice_qp_delta,
        "no_output_of_prior_pics_flag": no_output,
        "pps_id": pps_id,
        "slice_type": slice_type,
        "slice_sao_luma_flag": slice_sao_luma_flag,
        "slice_sao_chroma_flag": slice_sao_chroma_flag,
        "body_byte_offset": body_byte_offset,
        "body_bytes": deemul[body_byte_offset:],
    }


def _build_phantom_slice_with_pocs(
    idr_nal: bytes,
    target_poc: int,
    sps: dict,
    pps: dict,
    idr_header_info: dict,
    keep_pocs: list[int],
) -> bytes:
    """Variant of :func:`_build_phantom_slice` that takes an explicit list of
    POCs to retain in the DPB. POCs in ``keep_pocs`` must all be < target_poc
    and will be declared as ``used=0`` negative-direction RPS entries."""
    deltas = sorted(
        ((target_poc - p) for p in keep_pocs if p < target_poc),
        reverse=False,
    )
    # deltas is a list of positive distances; sort ascending so the first
    # entry is the closest predecessor.
    encoded: list[int] = []
    prev = 0
    for d in deltas:
        encoded.append(d - prev - 1)
        prev = d
    return _build_phantom_slice(
        idr_nal,
        target_poc,
        sps,
        pps,
        idr_header_info,
        rps_neg_dpm1=encoded,
    )


def _build_phantom_slice(
    idr_nal: bytes,
    target_poc: int,
    sps: dict,
    pps: dict,
    idr_header_info: dict,
    rps_neg_dpm1: Optional[list[int]] = None,
    keep_prior_pocs: int = 0,
) -> bytes:
    """Construct a TRAIL_R slice NAL at ``target_poc`` whose body is the
    IDR's intra-coded slice_segment_data.

    ``keep_prior_pocs`` is the number of consecutive prior POCs to retain
    in the DPB via this slice's RPS. Required so the chain of phantoms
    cumulatively builds up the DPB instead of each phantom evicting its
    predecessors. All retained references are marked ``used=0`` — they
    are *kept in DPB* but not used as motion-compensation predictors by
    this I-slice phantom.
    """

    # Phantom NAL header: TRAIL_R (type=1), layer_id=0, temporal_id_plus1=1.
    # byte 0 = forbidden_zero(1) | nal_unit_type(6) | layer_id_msb(1) = 00000010
    # byte 1 = layer_id_lsb(5) | temporal_id_plus1(3) = 00000001
    nal_header = bytes([0x02, 0x01])
    bw = _BitWriter(nal_header)

    # slice_segment_header()
    bw.b(1, 1)  # first_slice_segment_in_pic_flag
    # no_output_of_prior_pics_flag is IRAP-only — skip for TRAIL_R
    bw.ue(idr_header_info["pps_id"])  # same PPS id as the IDR
    for _ in range(pps["num_extra_slice_header_bits"]):
        bw.b(1, 0)
    bw.ue(2)  # slice_type = I
    if pps["output_flag_present"]:
        bw.b(1, 0)  # pic_output_flag = 0 (don't display the phantom)
    bw.b(sps["log2_max_poc_lsb"], target_poc)
    # short_term_ref_pic_set_sps_flag = 0 → use an inline RPS at index
    # num_short_term_ref_pic_sets. Inside st_ref_pic_set(), because the
    # index is non-zero we must precede the negative/positive counts with
    # inter_ref_pic_set_prediction_flag = 0 (we want an absolute RPS).
    bw.b(1, 0)  # short_term_ref_pic_set_sps_flag
    if sps["num_st_rps"] != 0:
        bw.b(1, 0)  # inter_ref_pic_set_prediction_flag
    # Inline RPS: each entry is encoded as a cumulative delta from the
    # previous (or from current POC for entry 0). We declare the
    # negative refs with used=0 — they sit in the DPB but this phantom
    # doesn't predict from them (we're an I-slice).
    if rps_neg_dpm1 is None:
        # Legacy path: emit ``keep_prior_pocs`` consecutive negative refs.
        rps_neg_dpm1 = [0] * keep_prior_pocs
    bw.ue(len(rps_neg_dpm1))  # num_negative_pics
    bw.ue(0)  # num_positive_pics
    for dpm1 in rps_neg_dpm1:
        bw.ue(dpm1)
        bw.b(1, 0)  # used_by_curr_pic_s0_flag = 0
    if sps["long_term_ref_pics_present"]:
        if sps["num_long_term_sps"] > 0:
            bw.ue(0)  # num_long_term_sps
        bw.ue(0)  # num_long_term_pics
    if sps["sps_temporal_mvp_enabled"]:
        bw.b(1, 0)  # slice_temporal_mvp_enabled_flag
    if sps["sample_adaptive_offset_enabled"]:
        # MUST mirror the IDR's SAO flags — the body byte stream is parsed
        # differently depending on whether SAO data is present per-CTU.
        bw.b(1, idr_header_info["slice_sao_luma_flag"])
        if sps["chroma_format_idc"] != 0:
            bw.b(1, idr_header_info["slice_sao_chroma_flag"])
    # I slice: skip P/B fields
    bw.se(idr_header_info["slice_qp_delta"])  # same QP so CABAC matches
    if pps["pps_slice_chroma_qp_offsets_present"]:
        bw.se(0)
        bw.se(0)
    # PPS toggles deblocking-override capability — when on, every slice
    # must carry deblocking_filter_override_flag. We default it to 0
    # (inherit PPS deblocking parameters).
    if pps["deblocking_filter_override_enabled"]:
        bw.b(1, 0)  # deblocking_filter_override_flag = 0
    # slice_loop_filter_across_slices_enabled_flag is conditional on
    # pps_loop_filter_across_slices_enabled — skipped when PPS has it 0.
    # Entry-point offsets: zero of them (phantom is a single sub-stream).
    if pps["tiles_enabled"] or pps["entropy_coding_sync_enabled"]:
        bw.ue(0)
    bw.byte_align()

    # Append the IDR's pre-extracted slice_segment_data verbatim. CABAC
    # decodes the same intra-coded macroblocks as the IDR did, producing
    # the same pixels — only the slice header POC label differs.
    raw = bw.bytes() + idr_header_info["body_bytes"]
    return _emul(raw)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def _parse_sps_rps_templates(sps_nal: bytes) -> list[list[int]]:
    """Return the SPS-defined short-term RPS templates as a list of
    (negative) POC deltas per template. Each template is the list of
    negative deltas (in iterated order). Inter-prediction between RPS
    entries is materialised in-place."""
    de = _deemul(sps_nal)
    r = _BitReader(de)
    r.b(4)
    max_sub = r.b(3)
    r.b(1)
    r.b(2)
    r.b(1)
    r.b(5)
    r.b(32)
    r.b(48)
    r.b(8)
    sub_p, lvl_p = [], []
    for _ in range(max_sub):
        sub_p.append(r.b(1))
        lvl_p.append(r.b(1))
    if max_sub > 0:
        for _ in range(max_sub, 8):
            r.b(2)
    for i in range(max_sub):
        if sub_p[i]:
            r.b(2)
            r.b(1)
            r.b(5)
            r.b(32)
            r.b(48)
        if lvl_p[i]:
            r.b(8)
    r.ue()
    cf = r.ue()
    if cf == 3:
        r.b(1)
    r.ue()
    r.ue()
    if r.b(1):
        r.ue()
        r.ue()
        r.ue()
        r.ue()
    r.ue()
    r.ue()
    r.ue()  # log2_max_poc_lsb_minus4
    spsslo = r.b(1)
    for _ in range(max_sub + 1 if not spsslo else 1):
        r.ue()
        r.ue()
        r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    r.ue()
    assert not r.b(1), "scaling list not handled"
    r.b(1)  # amp
    r.b(1)  # sao
    pcm = r.b(1)
    if pcm:
        r.b(4)
        r.b(4)
        r.ue()
        r.ue()
        r.b(1)
    n = r.ue()
    rps_list: list[list[int]] = []
    for idx in range(n):
        inter_pred = 0 if idx == 0 else r.b(1)
        if inter_pred:
            delta_idx_m1 = 0 if idx == n else r.ue()
            ref_idx = idx - (delta_idx_m1 + 1)
            sign = r.b(1)
            abs_drps_m1 = r.ue()
            delta_rps = -(abs_drps_m1 + 1) if sign else (abs_drps_m1 + 1)
            ref = rps_list[ref_idx]
            num_ref = len(ref)
            used_flags = [r.b(1) for _ in range(num_ref + 1)]
            for j in range(num_ref + 1):
                if not used_flags[j]:
                    r.b(1)
            # Reconstruct: combine ref-set deltas with delta_rps and filter
            # by sign. Approximate via the entries we've already parsed.
            new_neg = []
            # The ref's entries each shift by delta_rps; sentinel "0" for
            # the reference picture itself also shifted.
            shifted = [e + delta_rps for e in ref] + [delta_rps]
            for k, val in enumerate(shifted):
                if val < 0 and used_flags[k]:
                    new_neg.append(val)
            new_neg.sort(reverse=True)
            rps_list.append(new_neg)
        else:
            nn = r.ue()
            np_ = r.ue()
            neg = []
            d = 0
            for _ in range(nn):
                d -= r.ue() + 1
                r.b(1)  # used flag
                neg.append(d)
            for _ in range(np_):
                r.ue()
                r.b(1)
            rps_list.append(neg)
    return rps_list


def _parse_slice_rps(slice_nal: bytes, sps: dict, pps: dict, sps_nal: bytes) -> Optional[list[int]]:
    """Extract the absolute POC references from a slice's RPS — supports
    both inline and SPS-indexed forms. Returns the absolute reference POCs
    or None if we can't decode (e.g. inter-predicted inline RPS)."""
    import math

    nut = (slice_nal[0] >> 1) & 0x3F
    deemul = _deemul(slice_nal)
    r = _BitReader(deemul)
    fs = r.b(1)
    if 16 <= nut <= 23:
        r.b(1)
    r.ue()  # pps_id
    if not fs:
        return None
    for _ in range(pps["num_extra_slice_header_bits"]):
        r.b(1)
    r.ue()  # slice_type
    if pps["output_flag_present"]:
        r.b(1)
    poc = r.b(sps["log2_max_poc_lsb"])
    sps_flag = r.b(1)
    if sps_flag:
        if sps["num_st_rps"] > 1:
            nbits = max(1, math.ceil(math.log2(sps["num_st_rps"])))
            idx = r.b(nbits)
        else:
            idx = 0
        templates = _parse_sps_rps_templates(sps_nal)
        if idx >= len(templates):
            return None
        return [poc + d for d in templates[idx]]
    if sps["num_st_rps"] != 0 and r.b(1):  # inter_ref_pic_set_prediction_flag
        return None
    nn = r.ue()
    r.ue()  # num_positive_pics
    delta = 0
    refs: list[int] = []
    for _ in range(nn):
        dp = r.ue()
        r.b(1)  # used_by_curr_pic_s0_flag
        delta -= dp + 1
        refs.append(poc + delta)
    return refs


def build_phantoms_for_bootstrap(
    vps_nal: bytes,
    sps_nal: bytes,
    pps_nal: bytes,
    idr_nal: bytes,
    first_delta_nal: bytes,
) -> list[bytes]:
    """Synthesise the phantom NALs needed to bootstrap a decoder past the
    POC gap between the IDR and the first real delta.

    Algorithm:
      1. Parse the first delta's inline RPS to learn which POCs the encoder
         expects to be in the DPB (typically a sparse fixed set plus the
         two immediate predecessors).
      2. For each missing POC (i.e. every referenced POC that isn't 0=IDR),
         emit a TRAIL_R I-slice phantom cloned from the IDR body.
      3. Each phantom carries an RPS that retains all *prior* phantoms +
         the IDR, so the DPB cumulatively builds up to exactly what the
         first delta will need.

    If the first delta uses an SPS-indexed or inter-predicted RPS (the
    consistently-inline pattern we've observed isn't followed), no
    phantoms are emitted — the bitstream is forwarded as-is.
    """
    sps = _parse_sps(sps_nal)
    pps = _parse_pps(pps_nal)
    refs = _parse_slice_rps(first_delta_nal, sps, pps, sps_nal)
    if refs is None:
        return []
    # Drop POC=0 (the IDR is already in DPB) and any duplicates; sort
    # ascending so we emit oldest phantom first.
    needed = sorted({p for p in refs if p > 0})
    if not needed:
        return []
    idr_info = _read_idr_slice_header(idr_nal, sps, pps)
    phantoms: list[bytes] = []
    # Prior POCs each phantom must declare in its RPS to keep them in DPB.
    # Always include POC=0 (the IDR) so it survives every phantom.
    keep: list[int] = [0]
    for poc in needed:
        phantoms.append(
            _build_phantom_slice_with_pocs(
                idr_nal,
                poc,
                sps,
                pps,
                idr_info,
                keep_pocs=list(keep),  # snapshot
            )
        )
        keep.append(poc)
    return phantoms


def first_slice_poc(slice_nal: bytes, sps_nal: bytes, pps_nal: bytes) -> Optional[int]:
    """Parse the POC out of a slice NAL header. Returns None for IRAP slices
    (their POC is implicit 0) or for slices we can't parse."""
    nut = (slice_nal[0] >> 1) & 0x3F
    if nut >= 32:
        return None
    if nut in (19, 20, 21):
        return 0
    try:
        sps = _parse_sps(sps_nal)
        pps = _parse_pps(pps_nal)
    except Exception:
        return None
    deemul = _deemul(slice_nal)
    r = _BitReader(deemul)
    fs = r.b(1)
    if 16 <= nut <= 23:
        r.b(1)
    r.ue()
    if not fs:
        return None
    for _ in range(pps["num_extra_slice_header_bits"]):
        r.b(1)
    r.ue()  # slice_type
    if pps["output_flag_present"]:
        r.b(1)
    return r.b(sps["log2_max_poc_lsb"])
