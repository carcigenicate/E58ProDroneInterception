from enum import IntFlag

from scapy.layers.inet import UDP
from scapy.packet import Packet, bind_layers
from scapy.fields import XByteField, XByteEnumField, XNBytesField, LEIntField

class Command(IntFlag):
    """An enumeration of all the commands that the drone appears to be capable of,
    based on the recovered source code."""
    TAKEOFF = 0x01  # TODO: Not 100% sure about this. It's'a default, unnamed command in the code.
    STOP = 0x02
    GYRO_CHECK = 0x04
    ROLL = 0x08


class ControlModifier(IntFlag):
    HEADLESS = 0x01
    HL = 0x02  # TODO: Not sure what this stands for. Seems to mean no modifier?
    R = 0x04  # This is "R" as a result of decompilation
    HAND_FLOW = 0x80


class E58ProHeader(Packet):
    name = "E58ProHeader"
    fields_desc = [XByteField("payload_header", 0xEF),
                   XByteField("payload_type_1", None),
                   XByteField("payload_size", None),
                   XByteField("header_padding", 0)]

    def post_build(self, this_layer: bytes, payload: bytes) -> bytes:
        """Sets up the fields that should be handled automatically, like the payload type and size.
        Payload is the layers that this layer wraps."""
        if self.payload_type_1 is None or self.payload_size is None:
            # Marginally faster than plain "layer_start + size + layer_end + payload" when "inserting"
            mut_bytes = bytearray(this_layer)
            mut_bytes += payload
            if self.payload_type_1 is None:
                mut_bytes[1] = 0 if not payload else 0x20 if len(payload) == 2 else 0x02  # Eww
            if self.payload_size is None:
                mut_bytes[2] = len(this_layer) + len(payload)
            return bytes(mut_bytes)
        else:
            return this_layer + payload

class E58ProSecondaryHeader(Packet):
    name = "E58ProSecondaryHeader"
    fields_desc = [XByteField("payload_type_2", None),
                   XByteField("secondary_header_payload", None)]

    def post_build(self, this_layer: bytes, payload: bytes) -> bytes:
        if self.payload_type_2 is None or self.secondary_header_payload is None:
            mut_bytes = bytearray(this_layer)
            mut_bytes.extend(payload)
            if self.payload_type_2 is None:
                mut_bytes[0] = 0x02 if payload else 0x01
            if self.secondary_header_payload is None:
                mut_bytes[1] = 0x02 if payload else 0x65
            return bytes(mut_bytes)
        else:
            return this_layer + payload


class E58ProBasePayload(Packet):
    name = "E58ProBasePayload"
    fields_desc = [XNBytesField("unknown_block_1", 0x01, 2),
                   XByteField("extended_payload", 0x00),
                   XNBytesField("unknown_block_2", 0x00, 3),
                   LEIntField("sequence_number", 0x00),  # LE = Little-Endian
                   XNBytesField("unknown_block_3", 0x1400, 2),

                   # The "Controller Body" (0x66-0x99 section)
                   XNBytesField("controller_header", 0x6614, 2),
                   XByteField("right_vert", 0x80),
                   XByteField("right_horz", 0x80),
                   XByteField("left_vert", 0x80),
                   XByteField("left_horz", 0x80),
                   XByteField("command", 0x00),
                   XByteField("control_modifier", 0x02),  # What should the default be? 0 or 2?
                   XNBytesField("empty", 0x00, 10),
                   XByteField("checksum", None),
                   XByteField("controller_footer", 0x99),

                   XNBytesField("unknown_block_4",
                                # A shortcut so I don't need to write out 44 0x00s.
                                int.from_bytes(bytes([*([0x00] * 44), 0x32, 0x4B, 0x14, 0x2D, 0x00, 0x00]), "big"),
                                50)]

    def post_build(self, this_layer: bytes, payload: bytes) -> bytes:
        if self.checksum is None:
            mut_bytes = bytearray(this_layer)
            mut_bytes.extend(payload)
            acc = 0
            for byte in mut_bytes[14:31]:  # Somehow slicing is slightly faster than islice
                acc ^= byte
            mut_bytes[30] = acc  # Replace the checksum byte
            return bytes(mut_bytes)
        else:
            return this_layer + payload


# Any inbound UDP traffic with a destination port of 8800 will be parsed as the controller body
bind_layers(UDP, E58ProHeader, dport=8800)
bind_layers(E58ProHeader, E58ProSecondaryHeader)  # TODO: Need to specify filters?
bind_layers(E58ProSecondaryHeader, E58ProBasePayload)


def tests():
    p = E58ProBasePayload()

    assert len(p) == 0x52
    assert p.empty == 0x00
    assert E58ProBasePayload(bytes(p)).checksum == 0x02
