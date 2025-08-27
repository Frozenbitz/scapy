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


from scapy.all import (
    Packet,
    ByteField,
    ShortField,
    IntField,
    XIntField,
    StrFixedLenField,
    PacketListField
)

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


class OPC_UA_Binary(Packet):
    name = "OPC UA Binary"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        StrFixedLenField("MessageType", "", length=3),
        ByteField("ChunkType", "F"),
        IntField("ProtocolVersion", 0),
        IntField("ReceiveBufferSize", 8192),
        IntField("SendBufferSize", 8192),
        IntField("MaxMessageSize", 0),
        IntField("MaxChunkCount", 0),
        StrFixedLenField("EndpointUrl", ""),
        # PacketListField(
        #     "options", [], IPOption, length_from=lambda p: p.ihl * 4 - 20
        # ),  
    ]
