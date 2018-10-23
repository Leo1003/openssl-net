using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public abstract class OpenSslHandle : SafeHandle
    {
        protected OpenSslHandle(IntPtr ptr, bool ownsHandle) : base(IntPtr.Zero, ownsHandle)
        {
            SetHandle(ptr);
        }

        public override bool IsInvalid {
            get {
                return handle == IntPtr.Zero;
            }
        }

        protected abstract override bool ReleaseHandle();

        internal IntPtr Handle {
            get {
                return handle;
            }
        }
    }
}
