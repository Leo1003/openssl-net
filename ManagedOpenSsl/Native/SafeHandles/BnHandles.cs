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

        public static readonly BnHandle Null = new BnHandle(IntPtr.Zero, false);
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

        public static readonly BnCtxHandle Null = new BnCtxHandle(IntPtr.Zero, false);
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

        public static readonly BnGencbHandle Null = new BnGencbHandle(IntPtr.Zero, false);
    }
}
