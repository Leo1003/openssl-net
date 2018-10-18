using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void RSA_free(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_up_ref(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_size(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_bits(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_security_bits(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_generate_key_ex(IntPtr rsa, int bits, IntPtr e, IntPtr cb);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_check_key(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_public_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_private_encrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_public_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_private_decrypt(int flen, byte[] from, byte[] to, IntPtr rsa, int padding);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_sign(int type, byte[] m, uint m_length, byte[] sigret, out uint siglen, IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_verify(int type, byte[] m, uint m_length, byte[] sigbuf, uint siglen, IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_print(IntPtr bp, IntPtr rsa, int offset);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_set0_key(IntPtr rsa, IntPtr n, IntPtr e, IntPtr d);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_set0_factors(IntPtr rsa, IntPtr p, IntPtr q);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_set0_crt_params(IntPtr rsa, IntPtr dmp1, IntPtr dmq1, IntPtr iqmp);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_n(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_e(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_d(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_p(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_q(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_dmp1(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_dmq1(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr RSA_get0_iqmp(IntPtr rsa);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int RSA_get_version(IntPtr rsa);
    }
}
