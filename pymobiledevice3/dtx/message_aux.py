import io
import logging
from typing import Any, Union

from bpylist2 import archiver
from construct import Bytes, ConstructError, Peek

from .primitives import PNULL, PBuf, PDict, _primitive_value_con, _PrimitiveBase

logger = logging.getLogger(__name__)
_test_eof = Peek(Bytes(1))


class MessageAux(list[Any]):
    """An adapter that parse DISPTACH arguments from/to primitive dictionaries"""

    @classmethod
    def parse(cls, obj: Union[bytes, bytearray, memoryview], context, path):
        if len(obj) == 0:
            # interpret empty buffers as an empty list
            return []
        stream = io.BytesIO(obj)
        primitive_dict = _primitive_value_con._parse(stream, context, f"{path}.aux")
        if not isinstance(primitive_dict, dict):
            raise ConstructError(
                f"Expected a dictionary for MessageAux, got {type(primitive_dict).__name__}", path=path
            )
        if len(primitive_dict) != 1 or not isinstance(primitive_dict.get(PNULL), list):
            raise ConstructError(
                f"Expected a dictionary with a single PNULL key mapping to a list, got {primitive_dict}", path=path
            )
        converted_list = []
        for arg in primitive_dict[PNULL]:
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
                        raise ConstructError(
                            f"Failed to unarchive argument from buffer: {e}, buf={arg!r}", path=path
                        ) from e

        return converted_list

    @classmethod
    def build(cls, obj, context, path) -> bytes:
        if not obj:
            # nothing is written ¯\_(ツ)_/¯
            return b""
        converted_list = []
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
                    raise ConstructError(
                        f"Failed to archive argument {arg} of type <{type(arg).__name__}>: {e}", path=path
                    ) from e

        pdict = PDict({PNULL: converted_list})
        stream = io.BytesIO()
        _primitive_value_con._build(pdict, stream, context, f"{path}.aux")
        return stream.getvalue()
