using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class HmacCtxHandle : OpenSslHandle
    {
        internal HmacCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.HMAC_CTX_free(handle);
            return true;
        }
    }
}
