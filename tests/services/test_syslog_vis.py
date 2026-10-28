import pytest

from pymobiledevice3.services.syslog import decode_vis


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        # Hebrew; "ל" (D7 9C) arrives as "\M^\" -- a meta-control escape whose payload is a backslash
        (rb"MyApp[42] <Notice>: \M-W\M-)\M-W\M^\\M-W\M^U\M-W\M^]", "MyApp[42] <Notice>: שלום"),
        # CJK
        (rb"indexPath \M-f\M^H\M^V model \M-d\M-8\M-:\M-g\M-)\M-: - done", "indexPath 或 model 为空 - done"),
        (rb"\M-d\M-8\M^V\M-g\M^U\M^L", "世界"),
        # Emoji
        (rb"mood: \M-p\M^_\M^Y\M^B", "mood: 🙂"),
        # 0xA0 (low 7 bits == space) is octal-encoded
        (rb"voil\M-C\240!", "voilà!"),
        (rb"\346\210\226", "或"),
    ],
)
def test_decode_vis_utf8(wire: bytes, expected: str) -> None:
    assert decode_vis(wire).decode() == expected


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        (rb"\M-!\M-~\M^@\M^_\M^?", b"\xa1\xfe\x80\x9f\xff"),
        (b"\\M-\\", b"\xdc"),
    ],
)
def test_decode_vis_meta_boundaries(wire: bytes, expected: bytes) -> None:
    assert decode_vis(wire) == expected


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        # current Apple libc encodes a literal backslash as \134 (seen on the wire from iOS 27), older vis as \\
        (rb'"path":"\134/var\134/root"', rb'"path":"\/var\/root"'),
        (rb"C:\\Users\\M-f", rb"C:\Users\M-f"),
        (rb"C:\134Users\134M-f", rb"C:\Users\M-f"),
    ],
)
def test_decode_vis_backslash(wire: bytes, expected: bytes) -> None:
    assert decode_vis(wire) == expected


@pytest.mark.parametrize(
    "wire",
    [
        rb"esc \^[ bell \^G",
        rb"nul \000 esc \033 del \177",
        rb"\777",
        rb"abc\24",
        rb"abc\24x",
        b"abc\\",  # lone trailing backslash
        rb"abc\M-",
        rb"abc\M^",
        rb"abc\q def\Mx",
        b"a\\M- b\\M-\tc\\M-\nd",
        rb"\M^a \M^0",
        b"plain ASCII [123] <Notice>: nothing to decode",
        b"",
        "already UTF-8 已经是".encode(),
    ],
)
def test_decode_vis_leaves_other_sequences(wire: bytes) -> None:
    assert decode_vis(wire) == wire
