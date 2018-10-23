using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{

    public class PKCS12Handle : OpenSslHandle
    {
        internal PKCS12Handle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.PKCS12_free(handle);
            return true;
        }
    }
}
