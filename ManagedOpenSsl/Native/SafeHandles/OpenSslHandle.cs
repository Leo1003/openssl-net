using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native.SafeHandles
{
    public delegate void FreeHandleFunc(IntPtr ptr);

    public abstract class OpenSslHandle : SafeHandle
    {
        private readonly FreeHandleFunc freefunc;

        protected OpenSslHandle(IntPtr ptr, bool ownsHandle, FreeHandleFunc func = null) : base(IntPtr.Zero, ownsHandle)
        {
            SetHandle(ptr);
            freefunc = func;
        }

        public override bool IsInvalid {
            get {
                return handle == IntPtr.Zero;
            }
        }

        protected override bool ReleaseHandle()
        {
            if (freefunc == null) {
                return false;
            }
            freefunc(handle);
            return true;
        }

        internal IntPtr Handle {
            get {
                return handle;
            }
        }
    }

    public class OpenSslStaticHandle : OpenSslHandle
    {
        //Constructor for marshaling only
        protected OpenSslStaticHandle() : base(IntPtr.Zero, false)
        { }

        protected OpenSslStaticHandle(IntPtr ptr) : base(ptr, false)
        { }

        protected override bool ReleaseHandle()
        {
            //No need to free
            return true;
        }
    }
}
