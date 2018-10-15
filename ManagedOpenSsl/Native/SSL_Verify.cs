using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    [Flags]
    public enum SSL_Verify : int
    {
        NONE = 0x00,
        PEER = 0x01,
        FAIL_IF_NO_PEER_CERT = 0x02,
        CLIENT_ONCE = 0x04,
        POST_HANDSHAKE = 0x08,
    }
}
