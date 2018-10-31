using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    [Flags]
    public enum EVP_CIPH
    {
        STREAM_CIPHER = 0x0,
        ECB_MODE = 0x1,
        CBC_MODE = 0x2,
        CFB_MODE = 0x3,
        OFB_MODE = 0x4,
        CTR_MODE = 0x5,
        GCM_MODE = 0x6,
        CCM_MODE = 0x7,
        XTS_MODE = 0x10001,
        WRAP_MODE = 0x10002,
        OCB_MODE = 0x10003,
        MODE = 0xF0007,
        /* Set if variable length cipher */
        VARIABLE_LENGTH = 0x8,
        /* Set if the iv handling should be done by the cipher itself */
        CUSTOM_IV = 0x10,
        /* Set if the cipher's init() function should be called if key is NULL */
        ALWAYS_CALL_INIT = 0x20,
        /* Call ctrl() to init cipher parameters */
        CTRL_INIT = 0x40,
        /* Don't use standard key length function */
        CUSTOM_KEY_LENGTH = 0x80,
        /* Don't use standard block padding */
        NO_PADDING = 0x100,
        /* cipher handles random key generation */
        RAND_KEY = 0x200,
        /* cipher has its own additional copying logic */
        CUSTOM_COPY = 0x400,
        /* Allow use default ASN1 get/set iv */
        FLAG_DEFAULT_ASN1 = 0x1000,
        /* Buffer length in bits not bytes: CFB1 mode only */
        FLAG_LENGTH_BITS = 0x2000,
        /* Note if suitable for use in FIPS mode */
        FLAG_FIPS = 0x4000,
        /* Allow non FIPS cipher in FIPS mode */
        FLAG_NON_FIPS_ALLOW = 0x8000,
        /*
         * Cipher handles any and all padding logic as well as finalisation.
         */
        FLAG_CUSTOM_CIPHER = 0x100000,
        FLAG_AEAD_CIPHER = 0x200000,
        FLAG_TLS1_1_MULTIBLOCK = 0x400000,
        /* Cipher can handle pipeline operations */
        FLAG_PIPELINE = 0X800000,
    }
}
