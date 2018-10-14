using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_PKCS7_bio(IntPtr bp, IntPtr p7);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void PKCS7_free(IntPtr p7);
    }
}
