using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{

    public class ThreadLockHandle : OpenSslHandle
    {
        internal ThreadLockHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.CRYPTO_THREAD_lock_free(handle);
            return true;
        }
    }
}
