using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    [Flags]
    public enum SSL_Mode : uint
    {
        /// <summary>
        /// Allow SSL_write(..., n) to return r with 0 &lt; r &lt; n (i.e. report success
        /// when just a single record has been written):
        /// </summary>
        ENABLE_PARTIAL_WRITE = 0x00000001,
        /// <summary>
        /// Make it possible to retry SSL_write() with changed buffer location
        /// (buffer contents must stay the same!); this is not the default to avoid
        /// the misconception that non-blocking SSL_write() behaves like
        /// non-blocking write():
        /// </summary>
        ACCEPT_MOVING_WRITE_BUFFER = 0x00000002,
        /// <summary>
        /// Never bother the application with retries if the transport
        /// is blocking:
        /// </summary>
        AUTO_RETRY = 0x00000004,
        /// <summary>
        /// Don't attempt to automatically build certificate chain
        /// </summary>
        NO_AUTO_CHAIN = 0x00000008,
        RELEASE_BUFFERS = 0x00000010,
        SEND_CLIENTHELLO_TIME = 0x00000020,
        SEND_SERVERHELLO_TIME = 0x00000040,
        SEND_FALLBACK_SCSV = 0x00000080,
        ASYNC = 0x00000100,
    }
}
