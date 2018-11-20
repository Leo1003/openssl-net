using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class BioHandle : OpenSslHandle
    {
        internal BioHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.BIO_free(handle);
            return true;
        }
    }

    public class BioMethodHandle : OpenSslHandle
    {
        private BioMethodHandle() : base(IntPtr.Zero, false)
        {

        }

        internal BioMethodHandle(IntPtr ptr) : base(ptr, false)
        {

        }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }
}
