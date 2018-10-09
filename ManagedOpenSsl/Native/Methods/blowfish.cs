using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_set_key(IntPtr key, int len, byte[] data);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_encrypt(ref uint data, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_decrypt(ref uint data, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_ecb_encrypt(byte[] input, byte[] output, IntPtr key, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_cbc_encrypt(byte[] input, byte[] output, int length, IntPtr schedule, byte[] ivec, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_cfb64_encrypt(byte[] input, byte[] output, int length, IntPtr schedule, byte[] ivec, ref int num, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void BF_ofb64_encrypt(byte[] input, byte[] output, int length, IntPtr schedule, byte[] ivec, ref int num);
    }
}
