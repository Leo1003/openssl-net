using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    [Flags]
    public enum ASN1StrFlags : uint
    {
        ESC_2253 = 0x1,
        ESC_CTRL = 0x2,
        ESC_MSB = 0x4,
        ESC_QUOTE = 0x8,
        UTF8_CONVERT = 0x10,
        IGNORE_TYPE = 0x20,
        SHOW_TYPE = 0x40,
        DUMP_ALL = 0x80,
        DUMP_UNKNOWN = 0x100,
        DUMP_DER = 0x200,
        ESC_2254 = 0x400,

        RFC2253 = (ESC_2253 | ESC_CTRL | ESC_MSB | UTF8_CONVERT | DUMP_UNKNOWN | DUMP_DER ),
    }
}
