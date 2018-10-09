using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static
        int DSA_generate_parameters_ex(IntPtr dsa,
            int bits,
            byte[] seed,
            int seed_len,
            out int counter_ret,
            out IntPtr h_ret,
            bn_gencb_st callback);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_generate_key(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void DSA_free(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_up_ref(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_size(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_bits(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_security_bits(IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSAparams_print(IntPtr bp, IntPtr x);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_print(IntPtr bp, IntPtr x, int off);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_sign(int type, byte[] dgst, int dlen, byte[] sig, out uint siglen, IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_verify(int type, byte[] dgst, int dgst_len, byte[] sigbuf, int siglen, IntPtr dsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_set0_pqg(IntPtr d, IntPtr p, IntPtr q, IntPtr g);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int DSA_set0_key(IntPtr d, IntPtr pub_key, IntPtr priv_key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_get0_p(IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_get0_q(IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_get0_g(IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_get0_pub_key(IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr DSA_get0_priv_key(IntPtr d);
    }
}
