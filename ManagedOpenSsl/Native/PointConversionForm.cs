using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    /// <summary>
    /// The point conversion form as defined in X9.62 (ECDSA)
    /// for the encoding of a elliptic curve point(x, y)
    /// </summary>
    public enum PointConversionForm : int
    {
        /// <summary>
        /// The point is encoded as z||x
        /// </summary>
        COMPRESSED = 2,
        /// <summary>
        /// The point is encoded as 0x04||x||y
        /// </summary>
        UNCOMPRESSED = 4,
        /// <summary>
        /// the point is encoded as z||x||y
        /// </summary>
        HYBRID = 6,
    }
}
