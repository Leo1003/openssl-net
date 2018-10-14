using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr d2i_PKCS12_bio(IntPtr bp, IntPtr p12);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int i2d_PKCS12_bio(IntPtr bp, IntPtr p12);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr PKCS12_create(
            string pass,
            string name,
            IntPtr pkey,
            IntPtr cert,
            IntPtr ca,
            int nid_key,
            int nid_cert,
            int iter,
            int mac_iter,
            int keytype);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int PKCS12_parse(IntPtr p12, string pass, out IntPtr pkey, out IntPtr cert, out IntPtr ca);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void PKCS12_free(IntPtr p12);
    }
}
