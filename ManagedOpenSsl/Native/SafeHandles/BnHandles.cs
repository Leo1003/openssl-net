using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class BnHandle : OpenSslHandle
    {
        internal BnHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.BN_free(handle);
            return true;
        }
    }

    public class BnCtxHandle : OpenSslHandle
    {
        internal BnCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.BN_CTX_free(handle);
            return true;
        }
    }

    public class BnGencbHandle : OpenSslHandle
    {
        internal BnGencbHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.BN_GENCB_free(handle);
            return true;
        }
    }
}
