using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    /// <summary>
    /// BIO Close Options
    /// </summary>
    public enum BIO_Close
    {
        /// <summary>
        /// Don't close on free
        /// </summary>
        NoClose = 0,
        /// <summary>
        /// Close on free
        /// </summary>
        Close = 1
    }
}
