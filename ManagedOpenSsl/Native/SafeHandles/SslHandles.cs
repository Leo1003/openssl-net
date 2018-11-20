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

    public class SslMethodHandle : OpenSslStaticHandle
    {
        //Constructor for marshaling only
        private SslMethodHandle()
        { }

        internal SslMethodHandle(IntPtr ptr) : base(ptr)
        { }
    }

    public class SslCipherHandle : OpenSslStaticHandle
    {
        //Constructor for marshaling only
        private SslCipherHandle()
        { }

        internal SslCipherHandle(IntPtr ptr) : base(ptr)
        { }
    }
}
