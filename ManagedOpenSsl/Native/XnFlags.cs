using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    [Flags]
    public enum XnFlags : uint
    {
        COMPAT = 0,
        ESC_2253 = ASN1StrFlags.ESC_2253,
        ESC_CTRL = ASN1StrFlags.ESC_CTRL,
        ESC_MSB = ASN1StrFlags.ESC_MSB,
        ESC_QUOTE = ASN1StrFlags.ESC_QUOTE,
        UTF8_CONVERT = ASN1StrFlags.UTF8_CONVERT,
        IGNORE_TYPE = ASN1StrFlags.IGNORE_TYPE,
        SHOW_TYPE = ASN1StrFlags.SHOW_TYPE,
        DUMP_ALL = ASN1StrFlags.DUMP_ALL,
        DUMP_UNKNOWN = ASN1StrFlags.DUMP_UNKNOWN,
        DUMP_DER = ASN1StrFlags.DUMP_DER,
        ESC_2254 = ASN1StrFlags.ESC_2254,

        SEP_COMMA_PLUS = (0x1 << 16),
        SEP_CPLUS_SPC = (0x2 << 16),
        SEP_SPLUS_SPC = (0x3 << 16),
        SEP_MULTILINE = (0x4 << 16),
        SEP_MASK = (0xf << 16),

        DN_REV = (1 << 20),

        FN_SN = (0 << 21),
        FN_LN = (1 << 21),
        FN_OID = (2 << 21),
        FN_NONE = (3 << 21),
        FN_MASK = (0x3 << 21),

        SPC_EQ = (1 << 23),
        DUMP_UNKNOWN_FIELDS = (1 << 24),
        FN_ALIGN = (1 << 25),

        RFC2253 = (ASN1StrFlags.RFC2253 | SEP_COMMA_PLUS | DN_REV | FN_SN | DUMP_UNKNOWN_FIELDS),
        ONELINE = (ASN1StrFlags.RFC2253 | ESC_QUOTE | SEP_CPLUS_SPC | SPC_EQ | FN_SN),
        MULTILINE = (ESC_CTRL | ESC_MSB | SEP_MULTILINE | SPC_EQ | FN_LN | FN_ALIGN),
    }
}
