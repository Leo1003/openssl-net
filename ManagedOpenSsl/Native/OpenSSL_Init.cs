using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    internal enum OpenSSL_Init : ulong
    {
        None = 0x00000000,
        NO_LOAD_CRYPTO_STRINGS = 0x00000001,
        LOAD_CRYPTO_STRINGS = 0x00000002,
        ADD_ALL_CIPHERS = 0x00000004,
        ADD_ALL_DIGESTS = 0x00000008,
        NO_ADD_ALL_CIPHERS = 0x00000010,
        NO_ADD_ALL_DIGESTS = 0x00000020,
        LOAD_CONFIG = 0x00000040,
        NO_LOAD_CONFIG = 0x00000080,
        ASYNC = 0x00000100,
        ENGINE_RDRAND = 0x00000200,
        ENGINE_DYNAMIC = 0x00000400,
        ENGINE_OPENSSL = 0x00000800,
        ENGINE_CRYPTODEV = 0x00001000,
        ENGINE_CAPI = 0x00002000,
        ENGINE_PADLOCK = 0x00004000,
        ENGINE_AFALG = 0x00008000,
        // ZLIB = 0x00010000,
        ATFORK = 0x00020000,
        // BASE_ONLY = 0x00040000,
        /* OPENSSL_INIT flag range 0xfff00000 reserved for OPENSSL_init_ssl() */
        NO_LOAD_SSL_STRINGS = 0x00100000,
        LOAD_SSL_STRINGS = 0x00200000,
    }
}
