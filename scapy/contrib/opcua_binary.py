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
    bind_layers,
    bind_bottom_up,
)

from scapy.fields import (
    ByteField,
    FlagsField,
    MultipleTypeField,
    XByteField,
    LEShortField,
    IntField,
    LEIntField,
    StrLenField,
    StrFixedLenField,
    PacketListField,
    ConditionalField,
    LEIntEnumField,
    ByteEnumField,
    FieldLenField,
    FieldListField,
    LESignedIntField,
    LESignedLongField,
    XLEIntField,
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


class Generic_NodeId(Packet):
    name = "A generic node to showcase the encoding scheme"
    fields_desc = [
        XByteField("Request_Header_NodeID_Mask", 1),  # default should be 4B encoding
        ConditionalField(
            ByteField("Request_Header_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.Request_Header_NodeID_Mask == 0,
        ),
        ConditionalField(
            ByteField("Request_Header_Namespace_Index_4B", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Request_Header_NodeIdentifier_Numeric_4B", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Request_Header_NamespaceIndex_Default", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 2)
            or (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 4)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
        ConditionalField(
            LEIntField("Request_Header_NamespaceIndex_Numeric", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 2),
        ),
        ConditionalField(
            StrFixedLenField("Request_Header_NamespaceIndex_GUID", 0, length=16),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 4),
        ),
        ConditionalField(
            LEIntField("Request_Header_NodeIdentifier_String_Size", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
        ConditionalField(
            StrLenField(
                "Request_Header_NodeIdentifier_String",
                "",
                length_from=lambda pkt: pkt.Request_Header_NodeIdentifier_String_Size,
            ),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
    ]


_diagnosticInfo_flags = {
    0x01: "SymbolicId",
    0x02: "Namespace",
    0x04: "LocalizedText",
    0x08: "Locale",
    0x10: "AdditionalInfo",
    0x20: "InnerStatusCode",
    0x40: "InnerDiagnosticInfo",
    0x80: "unused",
}

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


# this will probably never be used
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


# these encodings here are needed to map the service layer to the binary protocol
# for other NodeIds we can create some additional types, but not for the different
# mappings required for the initial service layer
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


class BuiltIn_OPCUA_ExtensionObject(Packet):
    # builtin container object for structure and union data types
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.1.8
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.15
    name = "Builtin: Extension Object"
    fields_desc = [
        XByteField(
            "Extension_Object_NodeId_Mask", 0x01
        ),  # default should be 4B encoding
        ConditionalField(
            ByteField("Extension_Object_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.Extension_Object_NodeId_Mask == 0x00,
        ),
        ConditionalField(
            ByteField("Extension_Object_Namespace_Index", 0),
            lambda pkt: pkt.Extension_Object_NodeId_Mask == 0x01,
        ),
        ConditionalField(
            LEShortField("Extension_Object_Identifier_Numeric_4B", 0),
            lambda pkt: pkt.Extension_Object_NodeId_Mask == 0x01,
        ),
        ByteEnumField(
            "Encoding",
            1,  # binary body
            {0: "NO_BODY", 1: "ByteString", 2: "XmlElement"},
        ),
        LESignedIntField("Extension_Object_Body_Size", -1),
        ConditionalField(
            StrLenField(
                "Extension_Object_Body",
                "",
                length_from=lambda pkt: pkt.Extension_Object_Body_Size,
            ),
            lambda pkt: pkt.Extension_Object_Body_Size != -1,
        ),
    ]


class CustomParameter_StringUrls(Packet):
    # a type for creating arrays of string urls
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.2#_Ref153821547
    name = "Custom Parameter: String Urls"
    fields_desc = [
        LESignedIntField("StringUrl_Size", -1),
        StrLenField(
            "StringUrl",
            None,
            length_from=lambda pkt: pkt.StringUrl_Size,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CustomParameter_GenericString(Packet):
    # a type for creating arrays of any string
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.4
    name = "Custom Parameter: Generic String"
    fields_desc = [
        LESignedIntField("GenericString_Size", -1),
        StrLenField(
            "GenericString",
            None,
            length_from=lambda pkt: pkt.GenericString_Size,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_ApplicationDescription(Packet):
    # a common set of information required to identify an application
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.2#_Ref153821547
    name = "Common Parameter: Struct ApplicationDescription"
    fields_desc = [
        LESignedIntField("ApplicationUri_Size", -1),
        ConditionalField(
            StrLenField(
                "ApplicationUri",
                "",
                length_from=lambda pkt: pkt.ApplicationUri_Size,
            ),
            lambda pkt: pkt.ApplicationUri_Size != -1,
        ),
        LESignedIntField("ProcuctUri_Size", -1),
        ConditionalField(
            StrLenField(
                "ProcuctUri",
                "",
                length_from=lambda pkt: pkt.ProcuctUri_Size,
            ),
            lambda pkt: pkt.ProcuctUri_Size != -1,
        ),
        # localized text for applicationName
        ByteEnumField(
            "ApplicationName_EncodingMask",
            1,  # binary body
            {1: "Locale", 2: "Normal Text", 3: "Locale and Text"},
        ),
        ConditionalField(
            LESignedIntField("ApplicationName_Locale_Size", -1),
            lambda pkt: (pkt.ApplicationName_EncodingMask == 1)
            or (pkt.ApplicationName_EncodingMask == 3),
        ),
        ConditionalField(
            StrLenField(
                "ApplicationName_Locale",
                "",
                length_from=lambda pkt: pkt.ApplicationName_Locale_Size,
            ),
            lambda pkt: (pkt.ApplicationName_EncodingMask == 1)
            or (pkt.ApplicationName_EncodingMask == 3)
            and (pkt.ApplicationName_Locale_Size != -1),
        ),
        ConditionalField(
            LESignedIntField("ApplicationName_Size", -1),
            lambda pkt: (pkt.ApplicationName_EncodingMask == 2)
            or (pkt.ApplicationName_EncodingMask == 3),
        ),
        ConditionalField(
            StrLenField(
                "ApplicationName",
                "",
                length_from=lambda pkt: pkt.ApplicationName_Size,
            ),
            lambda pkt: (pkt.ApplicationName_EncodingMask == 2)
            or (pkt.ApplicationName_EncodingMask == 3)
            and (pkt.ApplicationName_Size != -1),
        ),
        LEIntEnumField(
            "ApplicationType",
            1,
            {
                0: "Server",
                1: "Client",
                2: "Client AND Server",
                3: "Discovery Server",
            },
        ),
        LESignedIntField("GatewayServerUri_Size", -1),
        ConditionalField(
            StrLenField(
                "GatewayServerUri",
                "",
                length_from=lambda pkt: pkt.GatewayServerUri_Size,
            ),
            lambda pkt: pkt.GatewayServerUri_Size != -1,
        ),
        LESignedIntField("DiscoveryProfileUri_Size", -1),
        ConditionalField(
            StrLenField(
                "DiscoveryProfileUri",
                "",
                length_from=lambda pkt: pkt.DiscoveryProfileUri_Size,
            ),
            lambda pkt: pkt.DiscoveryProfileUri_Size != -1,
        ),
        # CustomParameter_StringUrls
        FieldLenField(
            "DiscoveryUrls_ArraySize",
            None,
            fmt="<I",
            count_of="DiscoveryUrls_Array",
        ),
        ConditionalField(
            PacketListField(
                "DiscoveryUrls_Array",
                None,
                CustomParameter_StringUrls,
                count_from=lambda pkt: pkt.DiscoveryUrls_ArraySize,
            ),
            lambda pkt: pkt.DiscoveryUrls_ArraySize != -1,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_ApplicationInstanceCertificate(Packet):
    # a structure for a single OPC UA application certificate
    # An ApplicationInstanceCertificate is a ByteString containing an encoded Certificate.
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.3#_Ref182127421

    name = "Common Parameter: Struct ApplicationInstanceCertificate"
    fields_desc = [
        LESignedIntField("AIC_VersionString_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_VersionString",
                "",
                length_from=lambda pkt: pkt.AIC_VersionString_Size,
            ),
            lambda pkt: pkt.AIC_VersionString_Size != -1,
        ),
        LESignedIntField("AIC_SerialNumber_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_SerialNumber",
                "",
                length_from=lambda pkt: pkt.AIC_SerialNumber_Size,
            ),
            lambda pkt: pkt.AIC_SerialNumber_Size != -1,
        ),
        LESignedIntField("AIC_SignatureAlgorithm_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_SignatureAlgorithm",
                "",
                length_from=lambda pkt: pkt.AIC_SignatureAlgorithm_Size,
            ),
            lambda pkt: pkt.AIC_SignatureAlgorithm_Size != -1,
        ),
        LESignedIntField("AIC_Signature_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_Signature",
                "",
                length_from=lambda pkt: pkt.AIC_Signature_Size,
            ),
            lambda pkt: pkt.AIC_Signature_Size != -1,
        ),
        LESignedIntField("AIC_Issuer_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_Issuer",
                "",
                length_from=lambda pkt: pkt.AIC_Issuer_Size,
            ),
            lambda pkt: pkt.AIC_Issuer_Size != -1,
        ),
        LESignedLongField("AIC_ValidFrom", 0),
        LESignedLongField("AIC_ValidTo", 0),
        # the subject struct is missing
        # subject
        LESignedIntField("AIC_ApplicationUri_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_ApplicationUri",
                "",
                length_from=lambda pkt: pkt.AIC_ApplicationUri_Size,
            ),
            lambda pkt: pkt.AIC_ApplicationUri_Size != -1,
        ),
        # here we need hostnames
        FieldLenField(
            "AIC_Hostnames_ArraySize",
            None,
            fmt="<i",
            count_of="AIC_Hostnames_Array",
        ),
        PacketListField(
            "AIC_Hostnames_Array",
            None,
            CustomParameter_GenericString,
            count_from=lambda pkt: pkt.AIC_Hostnames_ArraySize,
        ),
        LESignedIntField("AIC_PublicKey_Size", -1),
        ConditionalField(
            StrLenField(
                "AIC_PublicKey",
                "",
                length_from=lambda pkt: pkt.AIC_PublicKey_Size,
            ),
            lambda pkt: pkt.AIC_PublicKey_Size != -1,
        ),
        # here we need key usage
        FieldLenField(
            "AIC_KeyUsage_ArraySize",
            None,
            fmt="<i",
            count_of="AIC_KeyUsage_Array",
        ),
        PacketListField(
            "AIC_KeyUsage_Array",
            None,
            CustomParameter_GenericString,
            count_from=lambda pkt: pkt.AIC_KeyUsage_ArraySize,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_UserTokenPolicy(Packet):
    # a structure to hold a single user (auth) policy
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.42#_Ref184567336

    name = "Common Parameter: Struct UserTokenPolicy"
    fields_desc = [
        LESignedIntField("UTP_PolicyId_Size", -1),
        ConditionalField(
            StrLenField(
                "UTP_PolicyId",
                "",
                length_from=lambda pkt: pkt.UTP_PolicyId_Size,
            ),
            lambda pkt: pkt.UTP_PolicyId_Size != -1,
        ),
        LEIntEnumField(
            "UTP_TokenType",
            3,
            {0: "ANONYMOUS", 1: "USERNAME", 2: "CERTIFICATE", 3: "ISSUEDTOKEN"},
        ),
        LESignedIntField("UTP_IssuedTokenType_Size", -1),
        ConditionalField(
            StrLenField(
                "UTP_IssuedTokenType",
                "",
                length_from=lambda pkt: pkt.UTP_IssuedTokenType_Size,
            ),
            lambda pkt: pkt.UTP_IssuedTokenType_Size != -1,
        ),
        LESignedIntField("UTP_IssuerEndpointUrl_Size", -1),
        ConditionalField(
            StrLenField(
                "UTP_IssuerEndpointUrl",
                "",
                length_from=lambda pkt: pkt.UTP_IssuerEndpointUrl_Size,
            ),
            lambda pkt: pkt.UTP_IssuerEndpointUrl_Size != -1,
        ),
        LESignedIntField("UTP_SecurityPolicyUri_Size", -1),
        ConditionalField(
            StrLenField(
                "UTP_SecurityPolicyUri",
                "",
                length_from=lambda pkt: pkt.UTP_SecurityPolicyUri_Size,
            ),
            lambda pkt: pkt.UTP_SecurityPolicyUri_Size != -1,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_EndpointDescription(Packet):
    # a structure to hold a full endpoint configuration for a response packet
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.14#_Ref171928664

    name = "Common Parameter: Struct EndpointDescription"
    fields_desc = [
        LESignedIntField("ED_EndpointUrl_Size", -1),
        ConditionalField(
            StrLenField(
                "ED_EndpointUrl",
                "",
                length_from=lambda pkt: pkt.ED_EndpointUrl_Size,
            ),
            lambda pkt: pkt.ED_EndpointUrl_Size != -1,
        ),
        CommonParameter_ApplicationDescription,
        # An ApplicationInstanceCertificate is a ByteString containing an encoded Certificate.
        # CommonParameter_ApplicationInstanceCertificate,
        # we need bytestring here instead, not the custom type:
        LESignedIntField("ED_ServerCertificate_Encoded_Size", -1),
        ConditionalField(
            StrLenField(
                "ED_ServerCertificate_Encoded",
                "",
                length_from=lambda pkt: pkt.ED_ServerCertificate_Encoded_Size,
            ),
            lambda pkt: pkt.ED_ServerCertificate_Encoded_Size != -1,
        ),
        LEIntEnumField(
            "ED_MessageSecurity_Mode",
            3,
            {0: "INVALID", 1: "NONE", 2: "SIGN", 3: "SIGNANDENCRYPT"},
        ),
        LESignedIntField("ED_SecurityPolicyUri_Size", -1),
        ConditionalField(
            StrLenField(
                "ED_SecurityPolicyUri",
                "",
                length_from=lambda pkt: pkt.ED_SecurityPolicyUri_Size,
            ),
            lambda pkt: pkt.ED_SecurityPolicyUri_Size != -1,
        ),
        # user identity token array:
        FieldLenField(
            "ED_UserIdentityTokens_ArraySize",
            None,
            fmt="<i",
            count_of="ED_UserIdentityTokens_Array",
        ),
        PacketListField(
            "ED_UserIdentityTokens_Array",
            None,
            CommonParameter_UserTokenPolicy,
            count_from=lambda pkt: pkt.ED_UserIdentityTokens_ArraySize,
        ),
        LESignedIntField("ED_TransportProfileUri_Size", -1),
        ConditionalField(
            StrLenField(
                "ED_TransportProfileUri",
                "",
                length_from=lambda pkt: pkt.ED_TransportProfileUri_Size,
            ),
            lambda pkt: pkt.ED_TransportProfileUri_Size != -1,
        ),
        ByteField("ED_SecurityLevel", 0),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_DiagnosticInfo(Packet):
    # vendor related information
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.12
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/5.2.2.12

    # this type can hold multiple different codes and types!
    # generally the initial mask has the following meandings, regarding the containing header:
    # 0x00 : no data
    # 0x01 : symbolic id is present
    # 0x02 : Namespace is present
    # 0x04 : LocalizedText is present
    # 0x08 : Locale is present
    # 0x10 : Additional Info is present
    # 0x20 : Inner Status Code is present
    # 0x40 : Inner diagnostic Info is present
    name = "Common Parameter: Struct DiadnosticInfo"
    fields_desc = [
        FlagsField("DI_EncodingMask", 0, 8, _diagnosticInfo_flags),
        ConditionalField(
            LESignedIntField("DI_SymbolicId", -1),
            lambda pkt: pkt.DI_EncodingMask & "SymbolicId",
        ),
        ConditionalField(
            LESignedIntField("DI_NamespaceUri", -1),
            lambda pkt: pkt.DI_EncodingMask & "Namespace",
        ),
        ConditionalField(
            LESignedIntField("DI_Locale", -1),
            lambda pkt: pkt.DI_EncodingMask & "Locale",
        ),
        ConditionalField(
            LESignedIntField("DI_LocalizedText", -1),
            lambda pkt: pkt.DI_EncodingMask & "LocalizedText",
        ),
        ConditionalField(
            LESignedIntField("DI_AdditionalInfo_Size", -1),
            lambda pkt: pkt.DI_EncodingMask & "AdditionalInfo",
        ),
        ConditionalField(
            StrLenField(
                "DI_AdditionalInfo",
                "",
                length_from=lambda pkt: pkt.DI_AdditionalInfo_Size,
            ),
            lambda pkt: (pkt.DI_EncodingMask & "AdditionalInfo")
            and (pkt.DI_AdditionalInfo_Size != -1),
        ),
        ConditionalField(
            LEIntField("DI_Inner_StatusCode", 0),
            lambda pkt: pkt.DI_EncodingMask & "InnerStatusCode",
        ),
        # here could follow some inner diag info?
        # recursion wont work here
        # TODO not implemented, ....
        # ConditionalField(
        #     CommonParameter_DiagnosticInfo,
        #     lambda pkt: pkt.DI_EncodingMask & 'InnerDiagnosticInfo'
        # ),
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

    # WTF
    # https://stackoverflow.com/questions/8073508/scapy-adding-new-protocol-with-complex-field-groupings
    def extract_padding(self, s):
        return "", s


class CommonParameter_SignatureData(Packet):
    # a structure to hold digital signatures created with a certificate
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.37#_Ref153782728
    name = "Common Parameter: Struct SignatureData"
    fields_desc = [
        LESignedIntField("Algorithm_Uri_Size", -1),
        ConditionalField(
            StrLenField(
                "Algorithm_Uri",
                "",
                length_from=lambda pkt: pkt.Algorithm_Uri_Size,
            ),
            lambda pkt: pkt.Algorithm_Uri_Size != -1,
        ),
        # this is a bytestring
        # TODO: this will require some testing
        LESignedIntField("Signature_Size", -1),
        ConditionalField(
            FieldListField(
                "Signature",
                None,
                ByteField,
                count_from=lambda pkt: pkt.Signature_Size,
            ),
            lambda pkt: pkt.Signature_Size != -1,
        ),
    ]


class CommonParameter_ClientSignature(Packet):
    # a structure to hold digital signatures created with a certificate
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.37#_Ref153782728
    name = "Common Parameter: Struct SignatureData for ClientSignature"
    fields_desc = [
        LESignedIntField("ClientSignature_Algorithm_Uri_Size", -1),
        ConditionalField(
            StrLenField(
                "ClientSignature_Algorithm_Uri",
                "",
                length_from=lambda pkt: pkt.ClientSignature_Algorithm_Uri_Size,
            ),
            lambda pkt: pkt.ClientSignature_Algorithm_Uri_Size != -1,
        ),
        # this is a bytestring
        # TODO: this will require some testing
        LESignedIntField("ClientSignature_Size", -1),
        ConditionalField(
            FieldListField(
                "ClientSignature",
                None,
                ByteField,
                count_from=lambda pkt: pkt.ClientSignature_Size,
            ),
            lambda pkt: pkt.ClientSignature_Size != -1,
        ),
    ]


class CommonParameter_UserTokenSignature(Packet):
    # a structure to hold digital signatures created with a certificate
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.37#_Ref153782728
    name = "Common Parameter: Struct SignatureData for UserTokenSignature"
    fields_desc = [
        LESignedIntField("UserTokenSignature_Algorithm_Uri_Size", -1),
        ConditionalField(
            StrLenField(
                "UserTokenSignature_Algorithm_Uri",
                "",
                length_from=lambda pkt: pkt.UserTokenSignature_Algorithm_Uri_Size,
            ),
            lambda pkt: pkt.UserTokenSignature_Algorithm_Uri_Size != -1,
        ),
        # this is a bytestring
        # TODO: this will require some testing
        LESignedIntField("UserTokenSignature_Size", -1),
        ConditionalField(
            FieldListField(
                "UserTokenSignature",
                None,
                ByteField,
                count_from=lambda pkt: pkt.UserTokenSignature_Size,
            ),
            lambda pkt: pkt.UserTokenSignature_Size != -1,
        ),
    ]


class CommonParameter_SignedSoftwareCertificate(Packet):
    # struct to hold a serialized string of certificate data and a signature
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.38#_Ref180486734
    name = "Common Parameter: Struct SignedSoftwareCertificate"
    fields_desc = [
        LESignedIntField("CertificateData_Size", -1),
        ConditionalField(
            FieldListField(
                "CertificateData",
                None,
                ByteField,
                count_from=lambda pkt: pkt.CertificateData_Size,
            ),
            lambda pkt: pkt.CertificateData_Size != -1,
        ),
        LESignedIntField("CertificateDataSignature_Size", -1),
        ConditionalField(
            FieldListField(
                "CertificateDataSignature",
                None,
                ByteField,
                count_from=lambda pkt: pkt.CertificateDataSignature_Size,
            ),
            lambda pkt: pkt.CertificateDataSignature_Size != -1,
        ),
    ]


# this is a custom instance of extension object
# we need to find another way of encoding multiple instances of custom datatypes
class CommonParameter_UserIdentityToken(BuiltIn_OPCUA_ExtensionObject):
    name = "Common Parameter: Struct UserIdentityToken"


class CustomParameter_LocaleId(Packet):
    # the default string representation for a locale
    # the standard allows quite a different number of encodings for this
    # might need to be changed into a custom field in the future
    # https://reference.opcfoundation.org/Core/Part3/v105/docs/8.4
    name = "Custom Parameter: String LocaleId"
    fields_desc = [
        LESignedIntField("LocaleId_Size", 2),
        StrLenField(
            "LocaleId",
            None,
            length_from=lambda pkt: pkt.LocaleId_Size,
        ),
    ]

    def extract_padding(self, s):
        return "", s


class CommonParameter_RequestHeader(Packet):
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.33
    name = "Generic Service Request Header"
    fields_desc = [
        XByteField("Request_Header_NodeID_Mask", 1),  # default should be 4B encoding
        ConditionalField(
            ByteField("Request_Header_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.Request_Header_NodeID_Mask == 0,
        ),
        ConditionalField(
            ByteField("Request_Header_Namespace_Index_4B", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Request_Header_NodeIdentifier_Numeric_4B", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Request_Header_NamespaceIndex_Default", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 2)
            or (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 4)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
        ConditionalField(
            LEIntField("Request_Header_NamespaceIndex_Numeric", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 2),
        ),
        ConditionalField(
            StrFixedLenField("Request_Header_NamespaceIndex_GUID", 0, length=16),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 4),
        ),
        ConditionalField(
            LEIntField("Request_Header_NodeIdentifier_String_Size", 0),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
        ConditionalField(
            StrLenField(
                "Request_Header_NodeIdentifier_String",
                "",
                length_from=lambda pkt: pkt.Request_Header_NodeIdentifier_String_Size,
            ),
            lambda pkt: (pkt.Request_Header_NodeID_Mask == 3)
            or (pkt.Request_Header_NodeID_Mask == 5),
        ),
        XLELongField("Timestamp", 0),  # this is some sort of UTC stamp?
        LEIntField("RequestHandle", 0),
        XLEIntField("ReturnDiagnostics", 0),  # this should be a flags field?
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


class CommonParameter_ResponseHeader(Packet):
    # check part 6: https://reference.opcfoundation.org/Core/Part6/v105/docs/6.7
    # there are multiple changes to how the response needs to be parsed
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/7.34#_Ref115239340
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/6.7.4
    name = "Generic Service Response Header"
    fields_desc = [
        XLELongField("Timestamp", 0),  # this is some sort of UTC stamp?
        LEIntField("Response_RequestHandle", 0),
        LEIntField("Response_StatusCode", 0),
        CommonParameter_DiagnosticInfo,
        FieldLenField(
            "Response_StringTable_ArraySize",
            None,
            fmt="<i",
            count_of="Response_StringTable_Array",
        ),
        PacketListField(
            "Response_StringTable_Array",
            None,
            CustomParameter_GenericString,
            count_from=lambda pkt: pkt.Response_StringTable_ArraySize,
        ),
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
#                   OPC_UA_Binary_Message_OpenSecureChannelResponse
#                   OPC_UA_Binary_Message_CreateSessionRequest
#                   OPC_UA_Binary_Message_CreateSessionResponse
#
# ============================================================================ #


class OPC_UA_Binary_Message_OpenSecureChannelRequest(Packet):
    name = "OpenSecureChannelRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        CommonParameter_RequestHeader,
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


class OPC_UA_Binary_Message_OpenSecureChannelResponse(Packet):
    name = "OpenSecureChannelResponse Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        CommonParameter_ResponseHeader,
        LEIntField("ServerProtocolVersion", 0x00),
        # channel security token:
        LEIntField("SecureChannelId", 0x00),
        LEIntField("TokenId", 0x00),
        LESignedLongField("CreatedAt", 0x00),
        LEIntField("RevisedLifetime", 0x00),
        LESignedIntField("ServerNonce_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerNonce",
                "",
                length_from=lambda pkt: pkt.ServerNonce_Size,
            ),
            lambda pkt: pkt.ServerNonce_Size != -1,
        ),
    ]


class OPC_UA_Binary_Message_CreateSessionRequest(Packet):
    name = "CreateSessionRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        CommonParameter_RequestHeader,
        CommonParameter_ApplicationDescription,  # clientDescription
        LESignedIntField("ServerUri_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerUri",
                "",
                length_from=lambda pkt: pkt.ServerUri_Size,
            ),
            lambda pkt: pkt.ServerUri_Size != -1,
        ),
        LESignedIntField("EndpointUrl_Size", -1),
        ConditionalField(
            StrLenField(
                "EndpointUrl",
                "",
                length_from=lambda pkt: pkt.EndpointUrl_Size,
            ),
            lambda pkt: pkt.EndpointUrl_Size != -1,
        ),
        LESignedIntField("SessionName_Size", -1),
        ConditionalField(
            StrLenField(
                "SessionName",
                "",
                length_from=lambda pkt: pkt.SessionName_Size,
            ),
            lambda pkt: pkt.SessionName_Size != -1,
        ),
        LESignedIntField("ClientNonce_Size", -1),
        ConditionalField(
            StrLenField(
                "ClientNonce",
                "",
                length_from=lambda pkt: pkt.ClientNonce_Size,
            ),
            lambda pkt: pkt.ClientNonce_Size != -1,
        ),
        LESignedIntField("ClientCertificate_Size", -1),
        ConditionalField(
            StrLenField(
                "ClientCertificate",
                "",
                length_from=lambda pkt: pkt.ClientCertificate_Size,
            ),
            lambda pkt: pkt.ClientCertificate_Size != -1,
        ),
        LESignedLongField("RequestedSessionTimeout", 0),  # some weird timestamp
        LESignedIntField("MaxResponseMessageSize", 0),
    ]


class OPC_UA_Binary_Message_CreateSessionResponse(Packet):
    name = "CreateSessionResponse Service Message"
    # https://reference.opcfoundation.org/Core/Part4/v105/docs/5.7.2
    fields_desc = [
        CommonParameter_ResponseHeader,
        # this is the Session ID fully encoded:
        XByteField(
            "Response_SessionId_NodeID_Mask", 1
        ),  # default should be 4B encoding
        ConditionalField(
            ByteField("Response_SessionId_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.Response_SessionId_NodeID_Mask == 0,
        ),
        ConditionalField(
            ByteField("Response_SessionId_Namespace_Index_4B", 0),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Response_SessionId_NodeIdentifier_Numeric_4B", 0),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Response_SessionId_NamespaceIndex_Default", 0),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 2)
            or (pkt.Response_SessionId_NodeID_Mask == 3)
            or (pkt.Response_SessionId_NodeID_Mask == 4)
            or (pkt.Response_SessionId_NodeID_Mask == 5),
        ),
        ConditionalField(
            LEIntField("Response_SessionId_NamespaceIndex_Numeric", 0),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 2),
        ),
        ConditionalField(
            StrFixedLenField("Response_SessionId_NamespaceIndex_GUID", 0, length=16),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 4),
        ),
        ConditionalField(
            LEIntField("Response_SessionId_NodeIdentifier_String_Size", 0),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 3)
            or (pkt.Response_SessionId_NodeID_Mask == 5),
        ),
        ConditionalField(
            StrLenField(
                "Response_SessionId_NodeIdentifier_String",
                "",
                length_from=lambda pkt: pkt.Response_SessionId_NodeIdentifier_String_Size,
            ),
            lambda pkt: (pkt.Response_SessionId_NodeID_Mask == 3)
            or (pkt.Response_SessionId_NodeID_Mask == 5),
        ),
        # this is the AuthenticationToken fully encoded:
        XByteField(
            "Response_AuthenticationToken_NodeID_Mask", 1
        ),  # default should be 4B encoding
        ConditionalField(
            ByteField("Response_AuthenticationToken_Identifier_Numeric_2B", 0),
            lambda pkt: pkt.Response_AuthenticationToken_NodeID_Mask == 0,
        ),
        ConditionalField(
            ByteField("Response_AuthenticationToken_Namespace_Index_4B", 0),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Response_AuthenticationToken_NodeIdentifier_Numeric_4B", 0),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 1),
        ),
        ConditionalField(
            LEShortField("Response_AuthenticationToken_NamespaceIndex_Default", 0),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 2)
            or (pkt.Response_AuthenticationToken_NodeID_Mask == 3)
            or (pkt.Response_AuthenticationToken_NodeID_Mask == 4)
            or (pkt.Response_AuthenticationToken_NodeID_Mask == 5),
        ),
        ConditionalField(
            LEIntField("Response_AuthenticationToken_NamespaceIndex_Numeric", 0),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 2),
        ),
        ConditionalField(
            StrFixedLenField(
                "Response_AuthenticationToken_NamespaceIndex_GUID", 0, length=16
            ),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 4),
        ),
        ConditionalField(
            LEIntField("Response_AuthenticationToken_NodeIdentifier_String_Size", 0),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 3)
            or (pkt.Response_AuthenticationToken_NodeID_Mask == 5),
        ),
        ConditionalField(
            StrLenField(
                "Response_AuthenticationToken_NodeIdentifier_String",
                "",
                length_from=lambda pkt: pkt.Response_AuthenticationToken_NodeIdentifier_String_Size,
            ),
            lambda pkt: (pkt.Response_AuthenticationToken_NodeID_Mask == 3)
            or (pkt.Response_AuthenticationToken_NodeID_Mask == 5),
        ),
        LESignedLongField("RevisedSessionTimeous", -1),
        LESignedIntField("ServerNonce_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerNonce",
                "",
                length_from=lambda pkt: pkt.ServerNonce_Size,
            ),
            lambda pkt: pkt.ServerNonce_Size != -1,
        ),
        LESignedIntField("ServerCertificate_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerCertificate",
                "",
                length_from=lambda pkt: pkt.ServerCertificate_Size,
            ),
            lambda pkt: pkt.ServerCertificate_Size != -1,
        ),
        # next is the endpoint description
        FieldLenField(
            "ServerEndpoints_ArraySize",
            None,
            fmt="<i",
            count_of="ServerEndpoints_Array",
        ),
        PacketListField(
            "ServerEndpoints_Array",
            None,
            CommonParameter_EndpointDescription,
            count_from=lambda pkt: pkt.ServerEndpoints_ArraySize,
        ),
        FieldLenField(
            "ServerSoftwareCertificates_ArraySize",
            None,
            fmt="<i",
            count_of="ServerSoftwareCertificates_Array",
        ),
        PacketListField(
            "ServerSoftwareCertificates_Array",
            None,
            CommonParameter_EndpointDescription,
            count_from=lambda pkt: pkt.ServerSoftwareCertificates_ArraySize,
        ),
        LESignedIntField("ServerSignature_Algorithm_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerSignature_Algorithm",
                "",
                length_from=lambda pkt: pkt.ServerSignature_Algorithm_Size,
            ),
            lambda pkt: pkt.ServerSignature_Algorithm_Size != -1,
        ),
        LESignedIntField("ServerSignature_Signature_Size", -1),
        ConditionalField(
            StrLenField(
                "ServerSignature_Signature",
                "",
                length_from=lambda pkt: pkt.ServerSignature_Signature_Size,
            ),
            lambda pkt: pkt.ServerSignature_Signature_Size != -1,
        ),
        LESignedIntField("MaxRequestMessageSize", 0),
    ]


class OPC_UA_Binary_Message_ActivateSessionRequest(Packet):
    name = "ActivateSessionRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        CommonParameter_RequestHeader,
        CommonParameter_ClientSignature,
        FieldLenField(
            "ClientSoftwareCertificates_ArraySize",
            None,
            fmt="<i",
            count_of="ClientSoftwareCertificates",
        ),
        PacketListField(
            "ClientSoftwareCertificates_Array",
            None,
            CommonParameter_SignedSoftwareCertificate,
            count_from=lambda pkt: pkt.ClientSoftwareCertificates_ArraySize,
        ),
        FieldLenField(
            "LocaleIds_ArraySize",
            None,
            fmt="<i",
            count_of="LocaleIds_Array",
        ),
        PacketListField(
            "LocaleIds_Array",
            None,
            CustomParameter_LocaleId,
            count_from=lambda pkt: pkt.LocaleIds_ArraySize,
        ),
        # BuiltIn_OPCUA_ExtensionObject,
        CommonParameter_UserIdentityToken,
        CommonParameter_UserTokenSignature,
    ]


class OPC_UA_Binary_Message_ReadRequest(Packet):
    name = "ReadRequest Service Message"
    # 7.1.2.3 Hello Message
    # https://reference.opcfoundation.org/Core/Part6/v105/docs/7.1.2.3
    fields_desc = [
        CommonParameter_RequestHeader,
        LESignedLongField("maxAge", -1),
        LEIntEnumField(
            "TimestampsToReturn",
            3,
            {0: "SOURCE", 1: "SERVER", 2: "BOTH", 3: "NEITHER", 4: "INVALID"},
        ),
        FieldLenField("NodesToRead_ArraySize", None, fmt="<I", count_of="NodesToRead"),
        PacketListField(
            "NodesToRead",
            None,
            CommonParameter_ReadValueId,
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
        CommonParameter_RequestHeader,
        ByteField("DeleteSubscriptions", 0),
    ]


class OPC_UA_Binary_Message_CloseSecureChannelRequest(Packet):
    name = "CloseSecureChannelRequest Service Message"
    #
    fields_desc = [
        CommonParameter_RequestHeader,
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


# bind the initial node ids to the request and response service layers
# the 2B encoding is not realistic here, since the default service IDs would not
# fit in this type of encoding. However we might have issues, when this layer
# uses some GUID or String representation, since we cannot automatically map this
# to some service layer.
# bind_layers(
#     OPC_UA_Binary_EncodableMessageObject,
#     OPC_UA_Binary_Message_EncodedNodeId_2B, # cannot work
#     NodeId_EncodingMask=0x00,
# )

bind_layers(
    OPC_UA_Binary_EncodableMessageObject,
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    NodeId_EncodingMask=0x01,
)

# Bind the service request layers
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

# Bind the service response layers
bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_OpenSecureChannelResponse,
    NodeId_Identifier_Numeric_4B=449,
)

bind_layers(
    OPC_UA_Binary_Message_EncodedNodeId_4B,
    OPC_UA_Binary_Message_CreateSessionResponse,
    NodeId_Identifier_Numeric_4B=464,
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
