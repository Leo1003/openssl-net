using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class EvpMdHandle : OpenSslStaticHandle
    {
        //Constructor for marshaling only
        private EvpMdHandle()
        { }

        internal EvpMdHandle(IntPtr ptr) : base(ptr)
        { }
    }

    public class EvpMdCtxHandle : OpenSslHandle
    {
        internal EvpMdCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EVP_MD_CTX_free(handle);
            return true;
        }
    }

    public class EvpCipherHandle : OpenSslStaticHandle
    {
        //Constructor for marshaling only
        private EvpCipherHandle()
        { }

        internal EvpCipherHandle(IntPtr ptr) : base(ptr)
        { }

        public static readonly EvpCipherHandle Null = new EvpCipherHandle(IntPtr.Zero);
    }

    public class EvpCipherCtxHandle : OpenSslHandle
    {
        internal EvpCipherCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EVP_CIPHER_CTX_free(handle);
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
