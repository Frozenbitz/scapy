# SPDX-License-Identifier: GPL-2.0-or-later
# This file is under development

# @Date:   2025-08-26

# scapy.contrib.description = OPC UA
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


from typing import Optional, Union
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
)

from scapy.all import (
    bind_layers,
    bind_bottom_up,
)

from scapy.fields import Field, LESignedIntField
from scapy.layers.inet import TCP

# https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.5
# 7.1.5 Error handling
# When a protocol level error occurs that cannot be recovered, the Server shall
# send an Error Message to the Client and closes the TransportConnection gracefully.
# When the Client receives an Error Message it reports the error to the application
# and closes the TransportConnection gracefully. If a Client encounters a fatal
#  error, it shall report the error to the application and send a CloseSecureChannel
# Message. The Server shall close the TransportConnection gracefully when it
# receives the CloseSecureChannel Message.

# https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref164020643
_OPC_UA_Connection_Protocol_error = {
    # TODO: the codes are not correct, need to be looked up
    382312475: "Bad_TcpServerTooBusy",
    382312497: "Bad_TcpMessageTypeInvalid",
    382312564: "Bad_TcpSecureChannelUnknown",
    382312565: "Bad_TcpMessageTooLarge",
    382312566: "Bad_Timeout",
    382312567: "Bad_TcpNotEnoughResources",
    382312568: "Bad_TcpInternalError",
    382312569: "Bad_TcpEndpointUrlInvalid",
    382312570: "Bad_SecurityChecksFailed",
    382312571: "Bad_RequestInterrupted",
    382312572: "Bad_RequestTimeout",
    382312573: "Bad_SecureChannelClosed",
    382312574: "Bad_SecureChannelTokenUnknown",
    382312575: "Bad_CertificateUntrusted",
    382312576: "Bad_CertificateTimeInvalid",
    382312577: "Bad_CertificateIssuerTimeInvalid",
    382312578: "Bad_CertificateUseNotAllowed",
    382312579: "Bad_CertificateIssuerUseNotAllowed",
    382312580: "Bad_CertificateRevocationUnknown",
    382312582: "Bad_CertificateIssuerRevocationUnknown",
    382312583: "Bad_CertificateRevoked",
    382312723: "Bad_IssuerCertificateRevoked",
    382312726: "Bad_SequenceNumberInvalid",
    382312814: "Bad_ServiceUnsupported",
}


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


# ---------------------------------------------------------------------------- #


# Here is a list of common OPC UA error codes
# https://honeywellprocess.my.site.com/opcsupport/s/article/What-are-the-common-OPC-UA-Status-Code
# We might be able to map these

# the default header is structured like this for an hello message:
# +-----+----+----+-----+-----+-----+-----+-----+-----+
# | MT  | CT | MS | VER | RBS | SBS | MMS | MCC | EPU |
# +-----+----+----+-----+-----+-----+-----+-----+-----+
#   HEL   F    xx   0     65k   65k   xx    5k    str

# https://reference.opcfoundation.org/Core/Part6/v105/docs/7
# OPC Binary has a set of default packages and flags
# the initial handler uses:
#  1) message type: mandatory (https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.2)
# A three byte ASCII code that identifies the Message type.
#         The following values are defined at this time:
#           HEL a Hello Message.
#           ACK an Acknowledge Message.
#           ERR an Error Message.
#           RHE a ReverseHello Message.
#           The SecureChannel layer defines additional values which the OPC UA Connection Protocol layer shall accept.
#  2) chunk type: mandatory
#  3) version: tbd dont know
#  4) ReceiveBufferSize, we dont know how these are affected
#  5) SendBufferSize
#  6) MaxMessageSize
#  7) MaxChunkCount
#  8) EndpointUrl: (mandatory) opc.tcp://172.17.0.2:4840/


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


class OPC_UA_Binary_Ack(Packet):
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


class OPC_UA_Binary_OpenSecureChannel(Packet):
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


class OPC_UA_Binary_SecureConversationMessage(Packet):
    name = "OPC UA Binary MSG"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        IntField("SecureChannelId", 0),
        IntField("SecurityTokenId", 0),
        IntField("SequenceNumber", 0),
        IntField("RequestId", 0),
    ]


class OPC_UA_Binary_Error(Packet):
    name = "OPC UA Binary ERR"
    # 7.1.2.5 Error Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.5
    fields_desc = [
        IntField("Error", 0),
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


class OPC_UA_Binary(Packet):
    name = "OPC UA Binary Encoded Protocol"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        StrFixedLenField("MessageType", "MSG", length=3),
        StrFixedLenField("ChunkType", "F", 1),
        LEIntField("MessageSize", 0),
    ]


# how are answers properly handled?
# HTTP (layers/http.py) seems to do the same here:
#   bind_bottom_up(TCP, HTTP, sport=80)
#   bind_bottom_up(TCP, HTTP, dport=80)
#   bind_layers(TCP, HTTP, sport=80, dport=80)
#   bind_bottom_up(TCP, HTTP, sport=8080)
#   bind_bottom_up(TCP, HTTP, dport=8080)

bind_bottom_up(TCP, OPC_UA_Binary, dport=4840)
bind_bottom_up(TCP, OPC_UA_Binary, sport=4840)
bind_layers(TCP, OPC_UA_Binary, sport=4840, dport=4840)
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Hello, MessageType=b"HEL")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Ack, MessageType=b"ACK")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_OpenSecureChannel, MessageType=b"OPN")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_SecureConversationMessage, MessageType=b"MSG")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Error, MessageType=b"ERR")


# bind sublayers
bind_layers(OPC_UA_Binary_OpenSecureChannel, OPC_UA_Binary_EncodableMessageObject)
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
