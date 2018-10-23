using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class X509Handle : OpenSslHandle
    {
        internal X509Handle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_free(handle);
            return true;
        }
    }

    public class X509ReqHandle : OpenSslHandle
    {
        internal X509ReqHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_REQ_free(handle);
            return true;
        }
    }

    public class X509ExtensionHandle : OpenSslHandle
    {
        internal X509ExtensionHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_EXTENSION_free(handle);
            return true;
        }
    }

    public class X509InfoHandle : OpenSslHandle
    {
        internal X509InfoHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_INFO_free(handle);
            return true;
        }
    }

    public class X509NameHandle : OpenSslHandle
    {
        internal X509NameHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_NAME_free(handle);
            return true;
        }
    }

    public class X509StoreHandle : OpenSslHandle
    {
        internal X509StoreHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_STORE_free(handle);
            return true;
        }
    }

    public class X509StoreCtxHandle : OpenSslHandle
    {
        internal X509StoreCtxHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_STORE_CTX_free(handle);
            return true;
        }
    }

    public class X509ObjectHandle : OpenSslHandle
    {
        internal X509ObjectHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.X509_OBJECT_free(handle);
            return true;
        }
    }
}
