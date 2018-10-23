using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class ASN1IntegerHandle : OpenSslHandle
    {
        internal ASN1IntegerHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ASN1_INTEGER_free(handle);
            return true;
        }
    }

    public class ASN1TimeHandle : OpenSslHandle
    {
        internal ASN1TimeHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ASN1_TIME_free(handle);
            return true;
        }
    }

    public class ASN1Handle : OpenSslHandle
    {
        internal ASN1Handle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ASN1_STRING_free(handle);
            return true;
        }
    }

    public class ASN1ObjectHandle : OpenSslHandle
    {
        internal ASN1ObjectHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ASN1_OBJECT_free(handle);
            return true;
        }
    }
}
