using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void DH_free(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_up_ref(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_bits(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_size(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_security_bits(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_generate_parameters_ex(IntPtr dh, int prime_len, int generator, bn_gencb_st cb);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_generate_key(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_compute_key(byte[] key, IntPtr pub_key, IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_check(IntPtr dh, out int codes);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_set0_pqg(IntPtr dh, IntPtr p, IntPtr q, IntPtr g);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DH_set0_key(IntPtr dh, IntPtr pub_key, IntPtr priv_key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_get0_p(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_get0_q(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_get0_g(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_get0_priv_key(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DH_get0_pub_key(IntPtr dh);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DHparams_print(IntPtr bp, IntPtr x);
    }
}
