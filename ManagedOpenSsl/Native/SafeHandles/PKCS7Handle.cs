using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class PKCS7Handle : OpenSslHandle
    {
        internal PKCS7Handle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.PKCS7_free(handle);
            return true;
        }
    }
}
