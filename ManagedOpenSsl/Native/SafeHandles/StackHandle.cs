using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{

    public class StackHandle : OpenSslHandle
    {
        internal StackHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.OPENSSL_sk_free(handle);
            return true;
        }
    }
}
