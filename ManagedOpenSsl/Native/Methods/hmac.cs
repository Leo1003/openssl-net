using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr HMAC_CTX_new();

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int HMAC_CTX_reset(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void HMAC_CTX_free(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static UIntPtr HMAC_size(IntPtr ctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void HMAC_Init_ex(IntPtr ctx, byte[] key, int len, IntPtr md, IntPtr engine_impl);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void HMAC_Update(IntPtr ctx, byte[] data, UIntPtr len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void HMAC_Final(IntPtr ctx, byte[] md, ref uint len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr HMAC(IntPtr evp_md, byte[] key, int key_len, byte[] d, UIntPtr n, byte[] md, ref uint md_len);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int HMAC_CTX_copy(IntPtr dctx, IntPtr sctx);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr HMAC_CTX_get_md(IntPtr ctx);
    }
}
