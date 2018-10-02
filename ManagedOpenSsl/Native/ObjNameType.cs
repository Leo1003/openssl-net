using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    public enum ObjNameType
    {
        UNDEF = 0x00,
        MD_METH = 0x01,
        CIPHER_METH = 0x02,
        PKEY_METH = 0x03,
        COMP_METH = 0x04,
        NUM = 0x05,
    }
}
