from bpylist2 import archiver
from construct import Struct, Int32ul, Int16ul, Int64ul, Const, Prefixed, GreedyBytes, this, Adapter, Select, \
    GreedyRange, Switch, Int32sl, Default


class BplitAdapter(Adapter):
    def _decode(self, obj, context, path):
        return archiver.unarchive(obj)

    def _encode(self, obj, context, path):
        return archiver.archive(obj)


dtx_message_header_struct = Struct(
    'magic' / Const(0x1F3D5B79, Int32ul),
    'cb' / Int32ul,
    'fragmentId' / Int16ul,
    'fragmentCount' / Int16ul,
    'length' / Int32ul,
    'identifier' / Int32ul,
    'conversationIndex' / Int32ul,
    'channelCode' / Int32sl,
    'expectsReply' / Int32ul,
)

dtx_message_payload_header_struct = Struct(
    'flags' / Int32ul,
    'auxiliaryLength' / Int32ul,
    'totalLength' / Int64ul,
)

message_aux_t_struct = Struct(
    'magic' / Default(Int64ul, 0x1f0),
    'aux' / Prefixed(Int64ul, GreedyRange(Struct(
        '_empty_dictionary' / Select(Const(0xa, Int32ul), Int32ul),
        'type' / Int32ul,
        'value' / Switch(this.type, {2: BplitAdapter(Prefixed(Int32ul, GreedyBytes)), 3: Int32ul, 6: Int64ul},
                         default=GreedyBytes),
    )))
)


class MessageAux:
    def __init__(self):
        self.values = []

    def append_int(self, value: int):
        self.values.append({'type': 3, 'value': value})
        return self

    def append_long(self, value: int):
        self.values.append({'type': 6, 'value': value})
        return self

    def append_obj(self, value):
        self.values.append({'type': 2, 'value': value})
        return self

    def __bytes__(self):
        return message_aux_t_struct.build(dict(aux=self.values))
