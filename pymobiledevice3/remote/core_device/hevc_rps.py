"""Pre-decode detection of missing reference frames by HEVC slice-header RPS analysis.

Parse the slice header before feeding the decoder: if a P-slice's Reference
Picture Set references a POC no longer in the DPB, VideoToolbox would silently
conceal that frame (sometimes with no decode error at all), so we can fire the
recovery path proactively rather than wait for VT to report it.

Targets Apple's iOS DisplayService stream (``TilesPerFrame=1``); tile-specific
handling is not needed.

References:
- ITU-T H.265 7.3.2.2 (SPS), 7.3.6 (slice segment header),
  7.3.7 (st_ref_pic_set), 8.3.1 (POC derivation).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, cast

logger = logging.getLogger(__name__)


# NAL unit types we care about (ITU-T H.265 Table 7-1).
NAL_BLA_W_LP = 16
NAL_BLA_W_RADL = 17
NAL_BLA_N_LP = 18
NAL_IDR_W_RADL = 19
NAL_IDR_N_LP = 20
NAL_CRA_NUT = 21

IRAP_RANGE = range(NAL_BLA_W_LP, NAL_CRA_NUT + 1)  # 16..21
IDR_RANGE = (NAL_IDR_W_RADL, NAL_IDR_N_LP)  # 19, 20


def is_slice_nal(nal_unit_type: int) -> bool:
    """VCL slice NAL: types 0-9 (TRAIL/TSA/STSA/RADL/RASL) and 16-21 (IRAPs)."""
    return 0 <= nal_unit_type <= 9 or 16 <= nal_unit_type <= 21


def remove_emulation_prevention(data: bytes) -> bytes:
    """Strip ``00 00 03`` → ``00 00`` emulation-prevention from RBSP."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        if i + 2 < n and data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 3:
            out.append(0)
            out.append(0)
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


class _BitReader:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read1(self) -> int:
        byte = self._pos >> 3
        if byte >= len(self._data):
            return 0
        bit = 7 - (self._pos & 7)
        self._pos += 1
        return (self._data[byte] >> bit) & 1

    def read(self, n: int) -> int:
        out = 0
        for _ in range(n):
            out = (out << 1) | self.read1()
        return out

    def read_ue(self) -> int:
        """Unsigned exp-Golomb (HEVC ``ue(v)``). Bounded zeros loop guards
        against a malformed input spinning forever."""
        zeros = 0
        while self.read1() == 0 and zeros < 32:
            zeros += 1
        suffix = 0
        for i in range(zeros - 1, -1, -1):
            suffix |= self.read1() << i
        return (1 << zeros) - 1 + suffix


@dataclass()
class _ShortTermRps:
    deltas: list[tuple[int, bool]] = field(default_factory=list[tuple[int, bool]])


@dataclass()
class HevcSpsState:
    log2_max_pic_order_cnt_lsb: int = 8
    num_short_term_ref_pic_sets: int = 0
    short_term_rps_sets: list[_ShortTermRps] = field(default_factory=list[_ShortTermRps])
    num_long_term_ref_pics_sps: int = 0
    long_term_ref_pics_present_flag: bool = False
    separate_colour_plane_flag: bool = False
    pic_width_in_luma_samples: int = 0
    pic_height_in_luma_samples: int = 0
    log2_min_luma_coding_block_size_minus3: int = 0
    log2_diff_max_min_luma_coding_block_size: int = 0


def _skip_profile_tier_level(br: _BitReader, max_num_sub_layers: int) -> None:
    br.read(8)  # general_profile_space/tier/idc
    br.read(32)  # general_profile_compatibility_flag
    br.read(48)  # constraint flags + reserved + interop hints
    br.read(8)  # general_level_idc
    sub_layer_profile_present: list[int] = []
    sub_layer_level_present: list[int] = []
    for _ in range(max_num_sub_layers - 1):
        sub_layer_profile_present.append(br.read1())
        sub_layer_level_present.append(br.read1())
    if max_num_sub_layers > 1:
        for _ in range(max_num_sub_layers - 1, 8):
            br.read(2)  # reserved_zero_2bits[i]
    for i in range(max_num_sub_layers - 1):
        if sub_layer_profile_present[i]:
            br.read(8 + 32 + 48)
        if sub_layer_level_present[i]:
            br.read(8)


def _parse_st_ref_pic_set(
    br: _BitReader,
    idx: int,
    num_in_sps: int,
    sets: list[_ShortTermRps],
) -> _ShortTermRps:
    out = _ShortTermRps()
    inter_ref_pic_set_prediction_flag = 0
    if idx != 0:
        inter_ref_pic_set_prediction_flag = br.read1()

    if inter_ref_pic_set_prediction_flag:
        delta_idx_minus1 = 0
        if idx == num_in_sps:
            delta_idx_minus1 = br.read_ue()
        delta_rps_sign = br.read1()
        abs_delta_rps_minus1 = br.read_ue()
        delta_rps = (1 - 2 * delta_rps_sign) * (abs_delta_rps_minus1 + 1)
        ref_idx = idx - (delta_idx_minus1 + 1)
        if ref_idx < 0 or ref_idx >= len(sets):
            return out
        ref = sets[ref_idx]
        n_ref = len(ref.deltas) + 1
        used_by_curr = cast(list[int], [])
        use_delta: list[int] = []
        for _ in range(n_ref):
            used_by_curr.append(br.read1())
            udf = 1
            if not used_by_curr[-1]:
                udf = br.read1()
            use_delta.append(udf)
        for i, (rd, _used) in enumerate(reversed(ref.deltas)):
            d = rd + delta_rps
            if d < 0 and use_delta[i]:
                out.deltas.append((d, bool(used_by_curr[i])))
        if delta_rps < 0 and use_delta[n_ref - 1]:
            out.deltas.append((delta_rps, bool(used_by_curr[n_ref - 1])))
        return out

    num_negative_pics = br.read_ue()
    num_positive_pics = br.read_ue()
    last_neg = 0
    for _ in range(num_negative_pics):
        delta_poc_s0_minus1 = br.read_ue()
        used_by_curr = bool(br.read1())
        delta = last_neg - (delta_poc_s0_minus1 + 1)
        last_neg = delta
        out.deltas.append((delta, used_by_curr))
    last_pos = 0
    for _ in range(num_positive_pics):
        delta_poc_s1_minus1 = br.read_ue()
        used_by_curr = bool(br.read1())
        delta = last_pos + (delta_poc_s1_minus1 + 1)
        last_pos = delta
        out.deltas.append((delta, used_by_curr))
    return out


def parse_sps(rbsp: bytes) -> HevcSpsState:
    """Parse a HEVC SPS RBSP (no NAL header, emulation-prevention stripped)."""
    br = _BitReader(rbsp)
    state = HevcSpsState()

    br.read(4)  # sps_video_parameter_set_id
    sps_max_sub_layers_minus1 = br.read(3)
    br.read1()  # sps_temporal_id_nesting_flag
    _skip_profile_tier_level(br, sps_max_sub_layers_minus1 + 1)

    br.read_ue()  # sps_seq_parameter_set_id
    chroma_format_idc = br.read_ue()
    if chroma_format_idc == 3:
        state.separate_colour_plane_flag = bool(br.read1())
    state.pic_width_in_luma_samples = br.read_ue()
    state.pic_height_in_luma_samples = br.read_ue()
    if br.read1():  # conformance_window_flag
        br.read_ue()
        br.read_ue()
        br.read_ue()
        br.read_ue()

    br.read_ue()  # bit_depth_luma_minus8
    br.read_ue()  # bit_depth_chroma_minus8
    state.log2_max_pic_order_cnt_lsb = br.read_ue() + 4

    sub_layer_ordering_info_present_flag = br.read1()
    n_sub_lo = sps_max_sub_layers_minus1 + 1
    if not sub_layer_ordering_info_present_flag:
        n_sub_lo = 1
    for _ in range(n_sub_lo):
        br.read_ue()
        br.read_ue()
        br.read_ue()

    state.log2_min_luma_coding_block_size_minus3 = br.read_ue()
    state.log2_diff_max_min_luma_coding_block_size = br.read_ue()
    br.read_ue()
    br.read_ue()  # log2_min_transform / diff
    br.read_ue()
    br.read_ue()  # max_transform_hierarchy_depth_inter / intra

    if br.read1():  # scaling_list_enabled_flag  # noqa: SIM102 — bit-reader side effects; AND would change semantics
        if br.read1():  # sps_scaling_list_data_present_flag
            # scaling_list_data() is variable-size; skipping it
            # misaligns the bit cursor. Apple's iOS stream doesn't
            # use it in practice -- if a future build does, the
            # tracker will silently return empty results (parse
            # failure -> no opinion) and the post-decode error
            # path still catches tears.
            logger.warning("hevc_rps: SPS contains scaling_list_data; parser bails")
            return state

    br.read1()  # amp_enabled_flag
    br.read1()  # sample_adaptive_offset_enabled_flag
    if br.read1():  # pcm_enabled_flag
        br.read(4)
        br.read(4)
        br.read_ue()
        br.read_ue()
        br.read1()

    state.num_short_term_ref_pic_sets = br.read_ue()
    sets: list[_ShortTermRps] = []
    for i in range(state.num_short_term_ref_pic_sets):
        sets.append(_parse_st_ref_pic_set(br, i, state.num_short_term_ref_pic_sets, sets))
    state.short_term_rps_sets = sets

    state.long_term_ref_pics_present_flag = bool(br.read1())
    if state.long_term_ref_pics_present_flag:
        state.num_long_term_ref_pics_sps = br.read_ue()
    return state


def parse_slice_header_for_rps(
    nal_unit_type: int,
    rbsp_after_nal_header: bytes,
    sps: HevcSpsState,
) -> Optional[tuple[int, list[tuple[int, bool]]]]:
    """Parse the slice header just far enough to recover (poc_lsb, RPS).

    Returns ``None`` on parse failure or dependent segment -- callers
    treat that as 'no opinion' and feed the slice unconditionally.
    """
    try:
        br = _BitReader(rbsp_after_nal_header)
        first_slice_segment_in_pic_flag = br.read1()
        if nal_unit_type in IRAP_RANGE:
            br.read1()  # no_output_of_prior_pics_flag
        br.read_ue()  # slice_pic_parameter_set_id

        if not first_slice_segment_in_pic_flag:
            # Compute NumCtbsInPic to know how wide slice_segment_address is.
            min_cb_log2 = sps.log2_min_luma_coding_block_size_minus3 + 3
            ctb_log2 = min_cb_log2 + sps.log2_diff_max_min_luma_coding_block_size
            if ctb_log2 < 4 or ctb_log2 > 6 or sps.pic_width_in_luma_samples == 0:
                return None
            ctb_size = 1 << ctb_log2
            ctbs_w = (sps.pic_width_in_luma_samples + ctb_size - 1) // ctb_size
            ctbs_h = (sps.pic_height_in_luma_samples + ctb_size - 1) // ctb_size
            num_ctbs = ctbs_w * ctbs_h
            if num_ctbs <= 1:
                return None
            seg_addr_bits = (num_ctbs - 1).bit_length()
            br.read(seg_addr_bits)

        slice_type = br.read_ue()  # 0=B, 1=P, 2=I
        if sps.separate_colour_plane_flag:
            br.read(2)

        if nal_unit_type in IDR_RANGE:
            return (0, [])

        slice_pic_order_cnt_lsb = br.read(sps.log2_max_pic_order_cnt_lsb)
        short_term_ref_pic_set_sps_flag = br.read1()
        if not short_term_ref_pic_set_sps_flag:
            rps = _parse_st_ref_pic_set(
                br,
                sps.num_short_term_ref_pic_sets,
                sps.num_short_term_ref_pic_sets,
                sps.short_term_rps_sets,
            )
        elif sps.num_short_term_ref_pic_sets > 1:
            idx_bits = (sps.num_short_term_ref_pic_sets - 1).bit_length()
            idx = br.read(idx_bits)
            if idx >= len(sps.short_term_rps_sets):
                return None
            rps = sps.short_term_rps_sets[idx]
        else:
            if not sps.short_term_rps_sets:
                return (slice_pic_order_cnt_lsb, [])
            rps = sps.short_term_rps_sets[0]
        if slice_type == 2:
            return (slice_pic_order_cnt_lsb, [])
        return (slice_pic_order_cnt_lsb, list(rps.deltas))
    except Exception as e:
        logger.debug("hevc_rps: slice header parse failed: %s", e)
        return None


class HevcRpsTracker:
    """Single-tile DPB-shadow set. Feed SPS once, then for each AU:

    1. ``check_slice(slice_nal)`` -- returns the set of POCs the slice
       references that aren't in our seen-set. Non-empty => the
       decoder will conceal; caller fires PLI proactively.
    2. ``commit_decoded()`` -- after the AU was fed to VT, marks the
       slice's POC as 'in DPB' for future checks.

    Not thread-safe; expects a single asyncio recv-loop caller.
    """

    def __init__(self) -> None:
        self.sps: Optional[HevcSpsState] = None
        self._seen_pocs: set[int] = set()
        self._prev_poc_msb = 0
        self._prev_poc_lsb = 0
        self._last_checked_poc: Optional[int] = None
        self.checks = 0
        self.missing_ref_events = 0

    def reset(self) -> None:
        self._seen_pocs.clear()
        self._prev_poc_msb = 0
        self._prev_poc_lsb = 0
        self._last_checked_poc = None

    def feed_sps(self, sps_rbsp_with_nal_header: bytes) -> None:
        """``sps_rbsp_with_nal_header`` is the SPS NALU as captured by
        the depacketizer (NAL header + RBSP, emulation-prevention
        bytes still present). We strip both here."""
        try:
            if len(sps_rbsp_with_nal_header) < 3:
                return
            stripped = remove_emulation_prevention(sps_rbsp_with_nal_header[2:])
            self.sps = parse_sps(stripped)
            logger.debug(
                "hevc_rps: SPS log2_max_poc_lsb=%d pic=%dx%d num_st_rps=%d",
                self.sps.log2_max_pic_order_cnt_lsb,
                self.sps.pic_width_in_luma_samples,
                self.sps.pic_height_in_luma_samples,
                self.sps.num_short_term_ref_pic_sets,
            )
        except Exception as e:
            logger.warning("hevc_rps: SPS parse failed: %s", e)
            self.sps = None

    def check_slice(self, nalu: bytes) -> set[int]:
        """Returns the set of required POCs missing from our DPB shadow.
        Empty set = OK to feed (or unparseable, which we also treat as
        OK so we don't spuriously fire)."""
        self._last_checked_poc = None
        if self.sps is None or len(nalu) < 3:
            return set()
        nal_unit_type = (nalu[0] >> 1) & 0x3F
        rbsp = remove_emulation_prevention(nalu[2:])
        result = parse_slice_header_for_rps(nal_unit_type, rbsp, self.sps)
        if result is None:
            return set()
        poc_lsb, deltas = result
        max_poc_lsb = 1 << self.sps.log2_max_pic_order_cnt_lsb
        if nal_unit_type in IDR_RANGE:
            poc = 0
            self._prev_poc_msb = 0
            self._prev_poc_lsb = 0
        else:
            prev_msb = self._prev_poc_msb
            prev_lsb = self._prev_poc_lsb
            if poc_lsb < prev_lsb and (prev_lsb - poc_lsb) >= (max_poc_lsb // 2):
                cur_msb = prev_msb + max_poc_lsb
            elif poc_lsb > prev_lsb and (poc_lsb - prev_lsb) > (max_poc_lsb // 2):
                cur_msb = prev_msb - max_poc_lsb
            else:
                cur_msb = prev_msb
            poc = cur_msb + poc_lsb
            self._prev_poc_msb = cur_msb
            self._prev_poc_lsb = poc_lsb
        self.checks += 1
        self._last_checked_poc = poc
        missing: set[int] = set()
        for delta, used in deltas:
            if not used:
                continue
            ref_poc = poc + delta
            if ref_poc not in self._seen_pocs:
                missing.add(ref_poc)
        if missing:
            self.missing_ref_events += 1
        return missing

    def commit_decoded(self) -> None:
        """Mark the most recent ``check_slice``d POC as in the DPB."""
        poc = self._last_checked_poc
        if poc is None:
            return
        self._seen_pocs.add(poc)
        self._last_checked_poc = None
        # Prune the DPB shadow once it grows large -- prevents
        # unbounded memory on long sessions and also bounds the cost
        # of the membership tests above. 4096 POCs at 60 fps is over
        # a minute of history, well past any realistic reference
        # window (Apple uses very short reference chains).
        if len(self._seen_pocs) > 4096:
            keep = sorted(self._seen_pocs)[-1024:]
            self._seen_pocs = set(keep)


__all__ = [
    "IDR_RANGE",
    "IRAP_RANGE",
    "HevcRpsTracker",
    "HevcSpsState",
    "is_slice_nal",
    "parse_slice_header_for_rps",
    "parse_sps",
    "remove_emulation_prevention",
]
