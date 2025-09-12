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

from scapy.fields import (
    Field,
    FieldLenField,
    FieldListField,
    LEFieldLenField,
    LELongField,
    LESignedIntField,
    LESignedLongField,
    PacketLenField,
    UTCTimeField,
    XLE3BytesField,
    XLELongField,
)
from scapy.layers.inet import TCP

# these are too long to keep them in here for the formatter
# there might be some other way to export or generate these?
from scapy.contrib.opcua_binary_codes import _OPC_UA_Binary_Error_Codes

# ============================================================================ #
#
#       Field Definitions
#
#       These are additional field definitions, to handle the complex structure
#       of some messages related to the service calls
#
# ============================================================================ #


# we might add these in the future


# ============================================================================ #
#
#       Headers and Extension Packets
#
# ============================================================================ #


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


class AdditionalHeader(Packet):
    name = "Some appendix for the Request Header"
    fields_desc = [
        LEShortField("AdditionalHeader_NodeID", 0x00),  # 2-byte version
        ByteField("EncodingMask", 0x00),
    ]


class OPC_UA_Binary_Message_EncodedNodeId_2B(Packet):
    # this is a encoded nodeid for most systems:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.9
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.1.2
    # ExpandedNodeId: A NodeId that allows the namespace URI to be specified instead of an index.
    # the different possible encodings for special types are found here:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref105731689
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref131423295
    name = "Node Id: DataEncoding 2Byte format"
    fields_desc = [
        ByteField("NodeId_Identifier_Numeric_2B", 0x00),
    ]


class OPC_UA_Binary_Message_EncodedNodeId_4B(Packet):
    # this is a encoded nodeid for most systems:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.9
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.1.2
    # ExpandedNodeId: A NodeId that allows the namespace URI to be specified instead of an index.
    # the different possible encodings for special types are found here:
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref105731689
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref131423295
    name = "Node Id: DataEncoding 4Byte format"
    fields_desc = [
        ByteField("NodeId_Namespace_Index", b"00"),
        # numeric id for the 4-byte representation
        LEShortField("NodeId_Identifier_Numeric_4B", 0x00),
    ]


class BuiltIn_OPCUA_Binary_QualifiedName(Packet):
    # builtin encoding for qualified names
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.13
    name = "Builtin: OPCUA Binary QualifiedName"
    fields_desc = [
        LEShortField("QualifiedName_NSIDX", 0x01),  # the namespace index
        LESignedIntField("QualifiedName_Size", -1),
        ConditionalField(
            StrLenField(
                "QualifiedName",
                "",
                length_from=lambda pkt: pkt.QualifiedName_Size,
            ),
            lambda pkt: pkt.QualifiedName_Size != -1,
        ),
    ]


class CommonParameter_ReadValueId(Packet):
    # a structure to select a specific Node for reading values
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.29#_Ref133162567
    name = "Common Parameter: Struct ReadValueId"
    fields_desc = [
        XByteField("NodeID_EncodeMask", 0x01),  # default should be 4B encoding
        ConditionalField(
            ByteField("NodeId_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x00,
        ),
        ConditionalField(
            ByteField("NodeId_Namespace_Index", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x01,
        ),
        ConditionalField(
            LEShortField("NodeId_Identifier_Numeric_4B", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x01,
        ),
        LEIntField("AttributeId", 0),
        LESignedIntField("IndexRange_Size", -1),
        ConditionalField(
            StrLenField(
                "IndexRange",
                "",
                length_from=lambda pkt: pkt.IndexRange_Size,
            ),
            lambda pkt: pkt.IndexRange_Size != -1,
        ),
        BuiltIn_OPCUA_Binary_QualifiedName,
    ]


class RequestHeader(Packet):
    name = "Generic Service Request Header"
    fields_desc = [
        XByteField("NodeID_EncodeMask", 0x01),  # default should be 4B encoding
        ConditionalField(
            ByteField("NodeId_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x00,
        ),
        ConditionalField(
            ByteField("NodeId_Namespace_Index", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x01,
        ),
        ConditionalField(
            LEShortField("NodeId_Identifier_Numeric_4B", 0),
            lambda pkt: pkt.NodeID_EncodeMask == 0x01,
        ),
        XLELongField("Timestamp", 0),  # this is some sort of UTC stamp?
        LEIntField("RequestHandle", 0),
        LEIntField("ReturnDiagnostics", 0),  # this should be a flags field?
        LESignedIntField("AuditEntryIdSize", -1),
        ConditionalField(
            StrLenField(
                "AuditEntryId",
                "",
                length_from=lambda pkt: pkt.AuditEntryIdSize,
            ),
            lambda pkt: pkt.AuditEntryIdSize != -1,
        ),
        LEIntField("TimeoutHint", 0),
        AdditionalHeader,
    ]


# ============================================================================ #
# OPC UA Binary Message Headers:
#   this contains the top layers for the encoded message objects
#   body structure:
#
#   OPC_UA_Binary
#       OPC_UA_Binary_OpenSecureChannel
#       OPC_UA_Binary_SecureConversationMessage
#           OPC_UA_Binary_EncodableMessageObject
#               OPC_UA_Binary_Message_EncodedNodeId
#                   OPC_UA_Binary_Message_OpenSecureChannelRequest
#
# ============================================================================ #


class OPC_UA_Binary_Message_OpenSecureChannelRequest(Packet):
    name = "OpenSecureChannelRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        RequestHeader,
        LEIntField("ClientProtocolVersion", 0x00),
        LEIntField("SecurityTokenRequestType", 0x00),
        LEIntField("MessageSecurityMode", 0x00),
        LESignedIntField("ClientNonceSize", -1),
        ConditionalField(
            StrLenField(
                "ClientNonce",
                "",
                length_from=lambda pkt: pkt.ClientNonceSize,
            ),
            lambda pkt: pkt.ClientNonceSize != -1,
        ),
        LEIntField("RequestedLifetime", 0x00),
    ]


class OPC_UA_Binary_Message_CreateSessionRequest(Packet):
    name = "CreateSessionRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        RequestHeader,
    ]


class OPC_UA_Binary_Message_ActivateSessionRequest(Packet):
    name = "ActivateSessionRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        RequestHeader,
    ]


class OPC_UA_Binary_Message_ReadRequest(Packet):
    name = "ReadRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        RequestHeader,
        LESignedLongField("maxAge", -1),
        LEIntEnumField(
            "TimestampsToReturn",
            3,
            {0: "SOURCE", 1: "SERVER", 2: "BOTH", 3: "NEITHER", 4: "INVALID"},
        ),
        # the len field should be fine, appending a list of fields causes the issues atm...
        FieldLenField("NodesToRead_ArraySize", None, fmt="<I", count_of="NodesToRead"),
        # LESignedIntField("NodesToRead_ArraySize", 0),
        # the lookup fails, since we used a packet and not a field
        # we will need to build a field or find out how the packets are handled
        FieldListField(
            "NodesToRead",
            None,
            CommonParameter_ReadValueId(),
            count_from=lambda pkt: pkt.NodesToRead_ArraySize,
        ),
    ]


class OPC_UA_Binary_Message_CloseSessionRequest(Packet):
    """
    https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.4 \n

    This Service is used to terminate a Session. \n

    Service Results: \n
    Bad_SessionIdInvalid

    """

    name = "CloseSessionRequest Service Message"
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.4
    fields_desc = [
        RequestHeader,
        ByteField("DeleteSubscriptions", 0),
    ]


class OPC_UA_Binary_Message_CloseSecureChannelRequest(Packet):
    name = "CloseSecureChannelRequest Service Message"
    #
    fields_desc = [
        RequestHeader,
    ]


class OPC_UA_Binary_EncodableMessageObject(Packet):
    """
    This is the initial part of a message object following an OPN or MSG packet.
    Depending on the encoding, we need to choose a specific encoder for the NodeIDs
    and then decode the service Node that has been requested.
    """

    name = "Encodable Message Object"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        # this first byte selects how the bytes are represented
        # https://reference.opcfoundation.org/Core/Part6/v105/docs/?r=_Ref105731689
        XByteField("NodeId_EncodingMask", 0x01),
    ]


# ============================================================================ #
# OPC UA Binary Core Packets:
#   this contains the Binary Protocol, the different fields for the main message
#   body up to the encodable message objects:
#   OPC_UA_Binary
#       OPC_UA_Binary_Hello
#       OPC_UA_Binary_Acknowledge
#       OPC_UA_Binary_OpenSecureChannel
#       OPC_UA_Binary_SecureConversationMessage
#       OPC_UA_Binary_Error
#       OPC_UA_Binary_Close
#       OPC_UA_Binary_ReverseHello
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
#           CLO ...
#           MSG ...
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
        LESignedIntField("EndpointUriSize", -1),
        ConditionalField(
            StrLenField(
                "EndpointUri",
                "",
                length_from=lambda pkt: pkt.EndpointUriSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.EndpointUriSize != -1,  # if this is set,
        ),
    ]


# the default header structured for an reverse hello message:
# +-----+----+----+------+-----+
# | MT  | CT | MS | SURI | EPU |
# +-----+----+----+------+-----+
#   RHE   F    xx   str    str
#  4) ServerUri:
#  5) EndpointUri: (mandatory) e.g. opc.tcp://172.17.0.2:4840/
#
# If the understanding is correct, this type of packet is used to pass
# firewalls and other statefull entities.


class OPC_UA_Binary_ReverseHello(Packet):
    name = "OPC UA Binary RHE"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        LEIntField("ProtocolVersion", 0),
        LEIntField("ReceiveBufferSize", 8192),
        LEIntField("SendBufferSize", 8192),
        LEIntField("MaxMessageSize", 0),
        LEIntField("MaxChunkCount", 0),
        LESignedIntField("EndpointUriSize", -1),
        ConditionalField(
            StrLenField(
                "EndpointUri",
                "",
                length_from=lambda pkt: pkt.EndpointUriSize,
            ),  # The actual string data, condition_callable),
            lambda pkt: pkt.EndpointUriSize != -1,  # if this is set,
        ),
    ]


# TODO
# the default header structured for an ... message:
# +-----+----+----+-----+-----+-----+-----+-----+
# | MT  | CT | MS | VER | RBS | SBS | MMS | MCC |
# +-----+----+----+-----+-----+-----+-----+-----+
#   CLO   F    xx   0     65k   65k   xx    5k
#  4) version: (> this is some default, there is only one version so far )
#  5) ReceiveBufferSize
#  6) SendBufferSize
#  7) MaxMessageSize
#  8) MaxChunkCount


class OPC_UA_Binary_CloseSecureChannel(Packet):
    name = "OPC UA Binary CLO"
    # https://reference.opcfoundation.org/Core/Part6/v104/docs/6.7.2.2
    fields_desc = [
        LEIntField("SecureChannelId", 0),
        LEIntField("SecurityTokenId", 0),
        LEIntField("SequenceNumber", 0),
        LEIntField("RequestId", 0),
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


class OPC_UA_Binary_Acknowledge(Packet):
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
#
# Message Header: A three byte ASCII code that identifies the Message type.
# The following values are defined at this time:
# MSG A Message secured with the keys associated with a channel.
# OPN OpenSecureChannel Message.
# CLO CloseSecureChannel Message.
#  other than these we also should have: HEL, ERR, ?


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


# IMPORRTANT: we are still missing the chunking mechanism:
# https://reference.opcfoundation.org/Core/Part6/v104/docs/6.7.2#_Ref164007251
# This cannot be built with the current settings


# bind the main OPC Binary Layer:
bind_bottom_up(TCP, OPC_UA_Binary, dport=4840)
bind_bottom_up(TCP, OPC_UA_Binary, sport=4840)
bind_layers(TCP, OPC_UA_Binary, sport=4840, dport=4840)

# Bind the top message Layers (HEL,ACK,OPN,MSG,ERR):
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Hello, MessageType=b"HEL")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Acknowledge, MessageType=b"ACK")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_OpenSecureChannel, MessageType=b"OPN")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_SecureConversationMessage, MessageType=b"MSG")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_Error, MessageType=b"ERR")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_CloseSecureChannel, MessageType=b"CLO")
bind_layers(OPC_UA_Binary, OPC_UA_Binary_ReverseHello, MessageType=b"RHE")


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

bind_layers(
    OPC_UA_Binary_CloseSecureChannel,
    OPC_UA_Binary_EncodableMessageObject,
)


bind_layers(
    OPC_UA_Binary_EncodableMessageObject,
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    NodeId_EncodingMask=0x01,
)

# Bind the service layers
bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_OpenSecureChannelRequest,
    NodeId_Identifier_Numeric_4B=446,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_CreateSessionRequest,
    NodeId_Identifier_Numeric_4B=461,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_ActivateSessionRequest,
    NodeId_Identifier_Numeric_4B=467,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_ReadRequest,
    NodeId_Identifier_Numeric_4B=631,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_CloseSessionRequest,
    NodeId_Identifier_Numeric_4B=473,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_CloseSecureChannelRequest,
    NodeId_Identifier_Numeric_4B=452,
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
