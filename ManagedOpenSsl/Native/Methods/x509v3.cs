using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509V3_set_ctx(
            IntPtr ctx,
            IntPtr issuer,
            IntPtr subject,
            IntPtr req,
            IntPtr crl,
            int flags);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void X509V3_set_nconf(IntPtr ctx, IntPtr conf);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509V3_EXT_add_nconf(IntPtr conf, IntPtr ctx, byte[] section, IntPtr cert);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int X509V3_EXT_print(IntPtr bio, IntPtr ext, uint flag, int indent);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr X509V3_EXT_get_nid(int nid);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static IntPtr X509V3_EXT_conf_nid(IntPtr conf, IntPtr ctx, int ext_nid, string value);
    }
}
