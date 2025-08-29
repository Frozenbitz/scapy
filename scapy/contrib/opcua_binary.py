# SPDX-License-Identifier: GPL-2.0-or-later
# This file is under development

# @Date:   2025-08-26

# scapy.contrib.description = OPC Unified Automation Binary Protocol over TCP
# scapy.contrib.status = loads

"""
OPC Unified Architecture

Spec: OPC Foundation https://reference.opcfoundation.org/
OPC Mappings: https://reference.opcfoundation.org/Core/Part6/v105/docs/4
Data Encoding: https://reference.opcfoundation.org/Core/Part6/v105/docs/5
UA Binary Protocol: https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2
Message SecurityProtocols: https://reference.opcfoundation.org/Core/Part6/v105/docs/6
TransportProtocols: https://reference.opcfoundation.org/Core/Part6/v105/docs/7
"""


from scapy.all import (
    Packet,
    ByteField,
    XByteField,
    LEShortField,
    NBytesField,
    XNBytesField,
    IntField,
    SignedIntField,
    XIntField,
    LEIntField,
    XLEIntField,
    StrLenField,
    StrFixedLenField,
    PacketListField,
    MultipleTypeField,
    ConditionalField,
    EnumField,
    LEIntEnumField,
)

from scapy.all import (
    Packet,
    bind_layers,
    bind_bottom_up,
)

from scapy.fields import Field, LESignedIntField
from scapy.layers.inet import TCP

# these are too long to keep them in here for the formatter
# there might be some other way to export or generate these?
from scapy.contrib.opcua_binary_codes import _OPC_UA_Binary_Error_Codes


# https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref164020643
# these have been copied from another online source, these might need to be
# parsed some other way...
# https://python-opcua.readthedocs.io/en/latest/_modules/opcua/ua/status_codes.html
class OPC_UA_Binary_StatusCode(Packet):
    name = "Parses a single field containing a OPC UA StatusCode"
    fields_desc = [
        LEIntEnumField(
            "StatusCode",
            0x01,
            _OPC_UA_Binary_Error_Codes,
        ),
    ]


# ---------------------------------------------------------------------------- #


class OPC_UA_Binary_Message_EncodedNodeId(Packet):
    # this is a encoded nodeid for most systems:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.9
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.1.2
    # ExpandedNodeId: A NodeId that allows the namespace URI to be specified instead of an index.
    # the different possible encodings for special types are found here:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref105731689
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref131423295
    name = "Node Id: DataEncoding"
    fields_desc = [
        # this first byte selects how the bytes are represented
        # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref105731689
        ByteField("NodeId_EncodingMask", b"01"),
        ByteField("NodeId_Namespace_Index", b"00"),
        # numeric id for the 4-byte representation
        LEShortField("NodeId_Identifier_Numeric", 0),
    ]


class OPC_UA_Binary_Message_OpenSecureChannelRequest(Packet):
    name = "Open SecureChannel Request"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        StrFixedLenField("tbd", "MSG", length=4),
    ]


class OPC_UA_Binary_EncodableMessageObject(Packet):
    name = "Encodable Message Object"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        OPC_UA_Binary_Message_EncodedNodeId,
        OPC_UA_Binary_Message_OpenSecureChannelRequest,
    ]


# ============================================================================ #
# OPC UA Binary Core Packets:
#   this contains the Binary Protocol, the different fields for the main message
#   body up to the encodable message objects:
#   OPC_UA_Binary
#       OPC_UA_Binary_Hello
#       OPC_UA_Binary_Hello_ack
#       OPC_UA_Binary_OpenSecureChannel
#       OPC_UA_Binary_SecureConversationMessage
#       OPC_UA_Binary_Error
#
# ============================================================================ #
#
# https://reference.opcfoundation.org/Core/Part6/v105/docs/7
# OPC Binary has a set of default packages and flags
# the initial handler uses:
#  1) message type: mandatory
#       (https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.2)
# A three byte ASCII code that identifies the Message type (MT).
#         The following values are defined at this time:
#           HEL a Hello Message.
#           ACK an Acknowledge Message.
#           ERR an Error Message.
#           RHE a ReverseHello Message. (we usually find ACK?)
#           The SecureChannel layer defines additional values which the OPC UA
#            Connection Protocol layer shall accept. (we dont know which ones, fml)
#  2) chunk type: mandatory (> this is a reserved field, always F)
#  3) message size: mandatory
#       4) ... the different fields for the different messages (HEL,OPN,MSG,ERR)
#
# ============================================================================ #


# the default header structured for an hello message:
# +-----+----+----+-----+-----+-----+-----+-----+-----+
# | MT  | CT | MS | VER | RBS | SBS | MMS | MCC | EPU |
# +-----+----+----+-----+-----+-----+-----+-----+-----+
#   HEL   F    xx   0     65k   65k   xx    5k    str
#  4) version: (> this is some default, there is only one version so far )
#  5) ReceiveBufferSize
#  6) SendBufferSize
#  7) MaxMessageSize
#  8) MaxChunkCount
#  9) EndpointUrl: (mandatory) e.g. opc.tcp://172.17.0.2:4840/


class OPC_UA_Binary_Hello(Packet):
    name = "OPC UA Binary HEL"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        LEIntField("ProtocolVersion", 0),
        LEIntField("ReceiveBufferSize", 8192),
        LEIntField("SendBufferSize", 8192),
        LEIntField("MaxMessageSize", 0),
        LEIntField("MaxChunkCount", 0),
        LEIntField("EndpointUriSize", -1),  # 4-byte signed integer for length
        ConditionalField(
            StrLenField(
                "EndpointUri",
                "",
                length_from=lambda pkt: pkt.EndpointUriSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.EndpointUriSize != -1,  # if this is set,
        ),
    ]


# the default header structured for an hello ACK message:
# +-----+----+----+-----+-----+-----+-----+-----+
# | MT  | CT | MS | VER | RBS | SBS | MMS | MCC |
# +-----+----+----+-----+-----+-----+-----+-----+
#   ACK   F    xx   0     65k   65k   xx    5k
#  4) version: (> this is some default, there is only one version so far )
#  5) ReceiveBufferSize
#  6) SendBufferSize
#  7) MaxMessageSize
#  8) MaxChunkCount


class OPC_UA_Binary_Ack(Packet):
    """
    Class for handling OPC UA HEL ACK messages: \n
    4) version: (> this is some default, there is only one version so far ) \n
    5) ReceiveBufferSize \n
    6) SendBufferSize \n
    7) MaxMessageSize \n
    8) MaxChunkCount \n
    """

    name = "OPC UA Binary HEL ACK"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        LEIntField("ProtocolVersion", 0),
        LEIntField("ReceiveBufferSize", 8192),
        LEIntField("SendBufferSize", 8192),
        LEIntField("MaxMessageSize", 0),
        LEIntField("MaxChunkCount", 0),
    ]


# the default header structured for an OpenSecureChannel message:
# +-----+----+----+-----+-----+----+-----+----+-----+-----+
# | MT  | CT | MS | SCI | SPU | SC | RCT | SN | RID | MSG |
# +-----+----+----+-----+-----+----+-----+----+-----+-----+
#   OPN   F    xx   INT   str   str  str   int  int   xxx
#  4) SecureChannelID: this will be handled by the server
#  5) SecurityPolicyUri: String (array?) of selected Security Options
#  6) SenderCertificate: Sender Cert Chain
#  7) ReceiverCertificateThumbprint: ? Signature ?
#  8) Sequence Number: internal sequence id for requests on the selected endpoint
#  9) Message: encoded message object for the server, should be a service call
#               This is part of the next (bound) packet layer


class OPC_UA_Binary_OpenSecureChannel(Packet):
    """
    Class for handling OPC UA OPN messages: \n
    4) SecureChannelID: this will be handled by the server \n
    5) SecurityPolicyUri: String (array?) of selected Security Options \n
    6) SenderCertificate: Sender Cert Chain \n
    7) ReceiverCertificateThumbprint: ? Signature ? \n
    8) Sequence Number: internal sequence id for requests on the selected endpoint \n
    9) Message: encoded message object for the server, should be a service call \n
        This is part of the next (bound) packet layer
    """

    name = "OPC UA Binary OPN"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        LEIntField("SecureChannelId", 0),
        LESignedIntField("SecurityPolicyUriSize", -1),
        ConditionalField(
            StrLenField(
                "SecurityPolicyUri",
                "",
                length_from=lambda pkt: pkt.SecurityPolicyUriSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.SecurityPolicyUriSize != -1,  # if this is set,
        ),
        LESignedIntField("SenderCertificateSize", -1),
        ConditionalField(
            StrLenField(
                "SenderCertificate",
                "",
                length_from=lambda pkt: pkt.SenderCertificateSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.SenderCertificateSize != -1,  # if this is set,
        ),
        LESignedIntField("ReceiverCertificateThumbprintSize", -1),
        ConditionalField(
            StrLenField(
                "ReceiverCertificateThumbprint",
                "",
                length_from=lambda pkt: pkt.ReceiverCertificateThumbprintSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.ReceiverCertificateThumbprintSize != -1,  # if this is set,
        ),
        LEIntField("SequenceNumber", 0),
        LEIntField("RequestId", 0),
    ]


# the default header structured for an SecureConversationMessage:
# +-----+----+----+-----+-----+----+-----+-----+
# | MT  | CT | MS | SCI | STI | SN | RID | MSG |
# +-----+----+----+-----+-----+----+-----+-----+
#   OPN   F    xx   INT   INT   INT  INT   xxx
#  4) SecureChannelID: this will be handled by the server
#  5) SecurityTokenId: ?
#  6) Sequence Number: internal sequence id for requests on the selected endpoint
#  7) Request ID: internal id to map requests to a specific session? (maybe?)
#  8) Message: encoded message object for the server, should be a service call
#               This is part of the next (bound) packet layer


class OPC_UA_Binary_SecureConversationMessage(Packet):
    """
    Class for handling SecureConversationMessages:
    4) SecureChannelID: this will be handled by the server
    5) SecurityTokenId: ?
    6) Sequence Number: internal sequence id for requests on the selected endpoint
    7) Request ID: internal id to map requests to a specific session? (maybe?)
    8) Message: encoded message object for the server, should be a service call
        This is part of the next (bound) packet layer
    """

    name = "OPC UA Binary MSG"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        IntField("SecureChannelId", 0),
        IntField("SecurityTokenId", 0),
        IntField("SequenceNumber", 0),
        IntField("RequestId", 0),
    ]


# the default header structured for an ERROR message:
# +-----+----+----+-----+-----+
# | MT  | CT | MS | ERR | RSN |
# +-----+----+----+-----+-----+
#   ERR   F    xx   INT   str
#  4) ERROR: This is the official ID to map the issue
#  5) Reason: A textual but optional description of the error


class OPC_UA_Binary_Error(Packet):
    name = "OPC UA Binary ERR"
    # 7.1.2.5 Error Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.5
    fields_desc = [
        # XLEIntField("Error", 0),
        OPC_UA_Binary_StatusCode,
        LESignedIntField("ReasonSize", -1),
        ConditionalField(
            StrLenField(
                "Reason",
                "",
                length_from=lambda pkt: pkt.ReasonSize,
                max_length=4096,
            ),
            lambda pkt: pkt.ReasonSize != -1,
        ),
    ]


# the default header structured for an Binary message:
# +-----+----+----+
# | MT  | CT | MS | ...
# +-----+----+----+
#   OPN   F    xx
#  1) Message Type: this will be handled by the server
#  2) Reserved: Wireshark calls this the Chunk Type, must be "F"
#  3) Message Size: Size in Bytes
#  4) See any of the sublayers above (HEL, MSG, OPN ...)


class OPC_UA_Binary(Packet):
    """
    OPC UA Binary Protocol Header, main layer for OPC over TCP \n
    Keep in mind, that OPC sends its data in Little Endian format, not BE! \n
    1) Message Type: this will be handled by the server \n
    2) Reserved: Wireshark calls this the Chunk Type, must be "F" \n
    3) Message Size: Size in Bytes \n
    4) See any of the sublayers above (HEL, MSG, OPN ...) \n
    """

    name = "OPC UA Binary Encoded Protocol over TCP"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        StrFixedLenField("MessageType", "MSG", length=3),
        StrFixedLenField("ChunkType", "F", 1),
        LEIntField("MessageSize", 0),
    ]


# bind the main OPC Binary Layer:
bind_bottom_up(TCP, OPC_UA_Binary, dport=4840)
bind_bottom_up(TCP, OPC_UA_Binary, sport=4840)
bind_layers(TCP, OPC_UA_Binary, sport=4840, dport=4840)

# Bind the top message Layers (HEL,ACK,OPN,MSG,ERR):
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Hello, MessageType=b"HEL")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Ack, MessageType=b"ACK")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_OpenSecureChannel, MessageType=b"OPN")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_SecureConversationMessage, MessageType=b"MSG")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Error, MessageType=b"ERR")


# Bind the OpenSecureChannel Services together:
bind_layers(
    OPC_UA_Binary_OpenSecureChannel,
    OPC_UA_Binary_EncodableMessageObject,
)

# Bind the SecureConversationMessage Services together:
bind_layers(
    OPC_UA_Binary_SecureConversationMessage,
    OPC_UA_Binary_EncodableMessageObject,
)

# ---------------------------------------------------------------------------- #


# parse some custom types:
# this would be a OPC String, if we use default conditionals
# fields_desc = [
#     LEIntField("StringLength", -1),  # 4-byte signed integer for length
#     ConditionalField(
#         StrLenField(
#             "data",
#             "",
#             length_from=lambda pkt: pkt.StringLength,
#         ),  # The actual string data, condition_callable),
#     ),
#     lambda pkt: pkt.StringLength != -1,  # if this is set,
# ]

# ------------------------ useless types ------------------------------------- #

# useless type: we cannot change the name in there dynamically
# class OpcUaString(Packet):
#     """
#     A Scapy Field for OPC UA Strings.
#     Encodes/decodes as a 4-byte little-endian length prefix
#     followed by UTF-8 encoded string data.
#     Handles NULL (-1) and empty (0) string lengths.
#     """

#     name = "OpcUaString"
#     fields_desc = [
#         LEIntField("StrSize", -1),  # 4-byte signed integer for length
#         ConditionalField(
#             StrLenField(
#                 self.localname, # this does not work
#                 "",
#                 length_from=lambda pkt: pkt.StrSize,
#             ),  # The actual string data, condition_callable),
#             lambda pkt: pkt.StrSize != -1,  # if this is set,
#         ),
#     ]

#     def __init__(self, name: str):
#         """
#         Adds a human readable name to the string for parsing
#         """
#         super().__init__()
#         self.localname = name
