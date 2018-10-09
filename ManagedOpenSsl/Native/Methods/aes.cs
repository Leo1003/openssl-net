using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr AES_options();


        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int AES_set_encrypt_key(IntPtr userKey, int bits, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int AES_set_decrypt_key(IntPtr userKey, int bits, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_encrypt(byte[] input, byte[] output, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_decrypt(byte[] input, byte[] output, IntPtr key);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_ecb_encrypt(byte[] input, byte[] output, IntPtr key, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_cbc_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_cfb128_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, ref int num, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_cfb1_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, ref int num, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_cfb8_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, ref int num, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_ofb128_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, ref int num);

        /* NB: the IV is _two_ blocks long */
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_ige_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, byte[] ivec, EncOperation enc);

        /* NB: the IV is _four_ blocks long */
        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void AES_bi_ige_encrypt(byte[] input, byte[] output, ulong length, IntPtr key, IntPtr key2, byte[] ivec, EncOperation enc);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int AES_wrap_key(IntPtr key, byte[] ivec, byte[] output, byte[] input, uint inlen);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int AES_unwrap_key(IntPtr key, byte[] ivec, byte[] output, byte[] input, uint inlen);
    }
}
