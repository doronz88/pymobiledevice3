import logging
from collections.abc import Mapping
from typing import Any, Union, cast

from bpylist2 import archiver
from bytestruct import BinaryBuildError, BinaryParseError, BytesLike

from . import ns_types as _ns_types
from .primitives import PNULL, PBuf, PDict, PInt64, PStr, _PrimitiveBase, build_primitive, parse_primitive

# Register the NSKeyedArchive proxy classes eagerly (see the identical call in dtx/message.py):
# a bare side-effect import is unsafe under PEP 810 lazy imports, and archiver.unarchive() is
# reached from this module's own aux-arg decoding.
_ns_types.register_ns_keyed_classes()

logger = logging.getLogger(__name__)


class MessageAux(list[Any]):
    """An adapter that parse DISPTACH arguments from/to primitive dictionaries"""

    @classmethod
    def parse(cls, obj: BytesLike) -> list[Any]:
        if len(obj) == 0:
            # interpret empty buffers as an empty list
            return []
        primitive_dict = parse_primitive(obj)
        if not isinstance(primitive_dict, dict):
            raise BinaryParseError(f"expected a dictionary, got {type(primitive_dict).__name__}", record="MessageAux")
        if len(cast(Any, primitive_dict)) != 1 or not isinstance(cast(Any, primitive_dict).get(PNULL), list):
            raise BinaryParseError(
                f"expected a dictionary with a single PNULL key mapping to a list, got {primitive_dict}",
                record="MessageAux",
            )
        converted_list: list[Any] = []
        for arg in cast(list[Any], primitive_dict[PNULL]):
            assert isinstance(arg, _PrimitiveBase), (
                f"Expected all arguments to be primitive types, got {type(arg).__name__}"
            )
            if arg is PNULL:
                logger.warning(f"Received a PNULL argument instead of an empty buffer, dict={primitive_dict!r}")
                converted_list.append(None)
            elif not isinstance(arg, PBuf):
                # primitive types are passed as-is
                # they extens the built-in types, so we can just pass them through without converting
                converted_list.append(arg)
            else:
                if len(arg) == 0:
                    converted_list.append(None)  # interpret empty buffers as None
                else:
                    try:
                        converted_list.append(archiver.unarchive(arg))
                    except Exception as e:
                        raise BinaryParseError(f"Failed to unarchive argument from buffer: {e}, buf={arg!r}") from e

        return converted_list

    @classmethod
    def build(cls, obj: Any) -> bytes:
        if not obj:
            # nothing is written ¯\_(ツ)_/¯
            return b""
        converted_list: list[Any] = []
        # translate everything that is not a primitive into a NSKeyedArchiver-encoded blob
        for arg in obj:
            if isinstance(arg, _PrimitiveBase):
                converted_list.append(arg)
            elif arg is None:
                # An empty buffer is placed instead of a PrimitiveNull ¯\_(ツ)_/¯
                converted_list.append(PBuf(b""))
            else:
                try:
                    converted_list.append(PBuf(archiver.archive(arg)))
                except Exception as e:
                    raise BinaryBuildError(
                        f"Failed to archive argument {arg} of type <{type(arg).__name__}>: {e}"
                    ) from e

        return build_primitive(PDict({PNULL: converted_list}))


def build_keyed_aux(values: Mapping[str, Union[str, int]]) -> bytes:
    """Serialise named strings and integers as the auxiliary data of a keyed message."""
    pdict = PDict()
    for key, value in values.items():
        # The receiver reads keys and string values as C strings, so they carry their terminator.
        pdict[PStr(f"{key}\0")] = [PStr(f"{value}\0") if isinstance(value, str) else PInt64(value)]
    return build_primitive(pdict)
