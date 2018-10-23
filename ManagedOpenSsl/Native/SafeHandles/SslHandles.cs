using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class SslHandle : OpenSslHandle
    {
        internal SslHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.SSL_free(handle);
            return true;
        }
    }

    public class SslCtxHandle : OpenSslHandle
    {
        internal SslCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.SSL_CTX_free(handle);
            return true;
        }
    }

    public class SslMethodHandle : OpenSslHandle
    {
        internal SslMethodHandle(IntPtr ptr) : base(ptr, false)
        {

        }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }

    public class SslCipher : OpenSslHandle
    {
        internal SslCipher(IntPtr ptr) : base(ptr, false)
        {

        }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }
}
