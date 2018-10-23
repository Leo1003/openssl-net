using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class EvpMdHandle : OpenSslHandle
    {
        internal EvpMdHandle(IntPtr ptr) : base(ptr, false)
        {

        }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }

    public class EvpCipherHandle : OpenSslHandle
    {
        internal EvpCipherHandle(IntPtr ptr) : base(ptr, false)
        {

        }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }

    public class EvpPKeyHandle : OpenSslHandle
    {
        internal EvpPKeyHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EVP_PKEY_free(handle);
            return true;
        }
    }
}
