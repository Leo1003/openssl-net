using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public class EcPointHandle : OpenSslHandle
    {
        internal EcPointHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EC_POINT_free(handle);
            return true;
        }
    }

    public class EcGroupHandle : OpenSslHandle
    {
        internal EcGroupHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EC_GROUP_free(handle);
            return true;
        }
    }

    public class EcKeyHandle : OpenSslHandle
    {
        internal EcKeyHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.EC_KEY_free(handle);
            return true;
        }
    }

    public class EcdsaSigHandle : OpenSslHandle
    {
        internal EcdsaSigHandle(IntPtr ptr, bool ownsHandle) : base(ptr, ownsHandle)
        {

        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ECDSA_SIG_free(handle);
            return true;
        }
    }
}
