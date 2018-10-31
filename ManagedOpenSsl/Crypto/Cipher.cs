// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using OpenSSL.Core;
using OpenSSL.Native;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Crypto
{
    #region Cipher
    /// <summary>
    /// Wraps the EVP_CIPHER object.
    /// </summary>
    public class Cipher : Base
    {
        internal Cipher(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {

        }

        /// <summary>
        /// Prints the LongName of this cipher.
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            bio.Write(LongName);
        }

        /// <summary>
        /// Not implemented, these objects should never be disposed
        /// </summary>
        protected override void ReleaseHandle()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns EVP_get_cipherbyname()
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static Cipher CreateByName(string name)
        {
            var buf = Encoding.ASCII.GetBytes(name);
            var ptr = NativeMethods.EVP_get_cipherbyname(buf);

            if (ptr == IntPtr.Zero)
                return null;

            return new Cipher(ptr, false);
        }

        /// <summary>
        /// Calls OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH)
        /// </summary>
        public static string[] AllNamesSorted {
            get { return new NameCollector(ObjNameType.CIPHER_METH, true).Result.ToArray(); }
        }

        /// <summary>
        /// Calls OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH)
        /// </summary>
        public static string[] AllNames {
            get { return new NameCollector(ObjNameType.CIPHER_METH, false).Result.ToArray(); }
        }

        #region Ciphers
        /// <summary>
        /// EVP_enc_null()
        /// </summary>
        public static Cipher Null = new Cipher(NativeMethods.EVP_enc_null(), false);

        /// <summary>
        /// EVP_des_ecb()
        /// </summary>
        public static Cipher DES_ECB = new Cipher(NativeMethods.EVP_des_ecb(), false);

        /// <summary>
        /// EVP_des_ede()
        /// </summary>
        public static Cipher DES_EDE = new Cipher(NativeMethods.EVP_des_ede(), false);

        /// <summary>
        /// EVP_des_ede3()
        /// </summary>
        public static Cipher DES_EDE3 = new Cipher(NativeMethods.EVP_des_ede3(), false);

        /// <summary>
        /// EVP_des_ede_ecb()
        /// </summary>
        public static Cipher DES_EDE_ECB = new Cipher(NativeMethods.EVP_des_ede_ecb(), false);

        /// <summary>
        /// EVP_des_ede3_ecb()
        /// </summary>
        public static Cipher DES_EDE3_ECB = new Cipher(NativeMethods.EVP_des_ede3_ecb(), false);

        /// <summary>
        /// EVP_des_cfb64()
        /// </summary>
        public static Cipher DES_CFB64 = new Cipher(NativeMethods.EVP_des_cfb64(), false);

        /// <summary>
        /// EVP_des_cfb1()
        /// </summary>
        public static Cipher DES_CFB1 = new Cipher(NativeMethods.EVP_des_cfb1(), false);

        /// <summary>
        /// EVP_des_cfb8()
        /// </summary>
        public static Cipher DES_CFB8 = new Cipher(NativeMethods.EVP_des_cfb8(), false);

        /// <summary>
        /// EVP_des_ede_cfb64()
        /// </summary>
        public static Cipher DES_EDE_CFB64 = new Cipher(NativeMethods.EVP_des_ede_cfb64(), false);

        /// <summary>
        /// EVP_des_ede3_cfb64()
        /// </summary>
        public static Cipher DES_EDE3_CFB64 = new Cipher(NativeMethods.EVP_des_ede3_cfb64(), false);

        /// <summary>
        /// EVP_des_ede3_cfb1()
        /// </summary>
        public static Cipher DES_EDE3_CFB1 = new Cipher(NativeMethods.EVP_des_ede3_cfb1(), false);

        /// <summary>
        /// EVP_des_ede3_cfb8()
        /// </summary>
        public static Cipher DES_EDE3_CFB8 = new Cipher(NativeMethods.EVP_des_ede3_cfb8(), false);

        /// <summary>
        /// EVP_des_ofb()
        /// </summary>
        public static Cipher DES_OFB = new Cipher(NativeMethods.EVP_des_ofb(), false);

        /// <summary>
        /// EVP_ded_ede_ofb()
        /// </summary>
        public static Cipher DES_EDE_OFB = new Cipher(NativeMethods.EVP_des_ede_ofb(), false);

        /// <summary>
        /// EVP_des_ede3_ofb()
        /// </summary>
        public static Cipher DES_EDE3_OFB = new Cipher(NativeMethods.EVP_des_ede3_ofb(), false);

        /// <summary>
        /// EVP_des_cbc()
        /// </summary>
        public static Cipher DES_CBC = new Cipher(NativeMethods.EVP_des_cbc(), false);

        /// <summary>
        /// EVP_des_ede_cbc()
        /// </summary>
        public static Cipher DES_EDE_CBC = new Cipher(NativeMethods.EVP_des_ede_cbc(), false);

        /// <summary>
        /// EVP_des_ede3_cbc()
        /// </summary>
        public static Cipher DES_EDE3_CBC = new Cipher(NativeMethods.EVP_des_ede3_cbc(), false);

        /// <summary>
        /// EVP_desx_cbc()
        /// </summary>
        public static Cipher DESX_CBC = new Cipher(NativeMethods.EVP_desx_cbc(), false);

        /// <summary>
        /// EVP_rc4()
        /// </summary>
        public static Cipher RC4 = new Cipher(NativeMethods.EVP_rc4(), false);

        /// <summary>
        /// EVP_rc4_40()
        /// </summary>
        public static Cipher RC4_40 = new Cipher(NativeMethods.EVP_rc4_40(), false);

        /// <summary>
        /// EVP_idea_ecb()
        /// </summary>
        public static Cipher Idea_ECB = new Cipher(NativeMethods.EVP_idea_ecb(), false);

        /// <summary>
        /// EVP_idea_cfb64()
        /// </summary>
        public static Cipher Idea_CFB64 = new Cipher(NativeMethods.EVP_idea_cfb64(), false);

        /// <summary>
        /// EVP_idea_ofb()
        /// </summary>
        public static Cipher Idea_OFB = new Cipher(NativeMethods.EVP_idea_ofb(), false);

        /// <summary>
        /// EVP_idea_cbc()
        /// </summary>
        public static Cipher Idea_CBC = new Cipher(NativeMethods.EVP_idea_cbc(), false);

        /// <summary>
        /// EVP_rc2_ecb()
        /// </summary>
        public static Cipher RC2_ECB = new Cipher(NativeMethods.EVP_rc2_ecb(), false);

        /// <summary>
        /// EVP_rc2_cbc()
        /// </summary>
        public static Cipher RC2_CBC = new Cipher(NativeMethods.EVP_rc2_cbc(), false);

        /// <summary>
        /// EVP_rc2_40_cbc()
        /// </summary>
        public static Cipher RC2_40_CBC = new Cipher(NativeMethods.EVP_rc2_40_cbc(), false);

        /// <summary>
        /// EVP_rc2_64_cbc()
        /// </summary>
        public static Cipher RC2_64_CBC = new Cipher(NativeMethods.EVP_rc2_64_cbc(), false);

        /// <summary>
        /// EVP_rc2_cfb64()
        /// </summary>
        public static Cipher RC2_CFB64 = new Cipher(NativeMethods.EVP_rc2_cfb64(), false);

        /// <summary>
        /// EVP_rc2_ofb()
        /// </summary>
        public static Cipher RC2_OFB = new Cipher(NativeMethods.EVP_rc2_ofb(), false);

        /// <summary>
        /// EVP_bf_ecb()
        /// </summary>
        public static Cipher Blowfish_ECB = new Cipher(NativeMethods.EVP_bf_ecb(), false);

        /// <summary>
        /// EVP_bf_cbc()
        /// </summary>
        public static Cipher Blowfish_CBC = new Cipher(NativeMethods.EVP_bf_cbc(), false);

        /// <summary>
        /// EVP_bf_cfb64()
        /// </summary>
        public static Cipher Blowfish_CFB64 = new Cipher(NativeMethods.EVP_bf_cfb64(), false);

        /// <summary>
        /// EVP_bf_ofb()
        /// </summary>
        public static Cipher Blowfish_OFB = new Cipher(NativeMethods.EVP_bf_ofb(), false);

        /// <summary>
        /// EVP_cast5_ecb()
        /// </summary>
        public static Cipher Cast5_ECB = new Cipher(NativeMethods.EVP_cast5_ecb(), false);

        /// <summary>
        /// EVP_cast5_cbc()
        /// </summary>
        public static Cipher Cast5_CBC = new Cipher(NativeMethods.EVP_cast5_cbc(), false);

        /// <summary>
        /// EVP_cast5_cfb64()
        /// </summary>
        public static Cipher Cast5_OFB64 = new Cipher(NativeMethods.EVP_cast5_cfb64(), false);

        /// <summary>
        /// EVP_cast5_ofb()
        /// </summary>
        public static Cipher Cast5_OFB = new Cipher(NativeMethods.EVP_cast5_ofb(), false);

#if OPENSSL_RC5_SUPPORT
		public static Cipher RC5_32_12_16_CBC = new Cipher(Native.EVP_rc5_32_12_16_cbc(), false);
		public static Cipher RC5_32_12_16_ECB = new Cipher(Native.EVP_rc5_32_12_16_ecb(), false);
		public static Cipher RC5_32_12_16_CFB64 = new Cipher(Native.EVP_rc5_32_12_16_cfb64(), false);
		public static Cipher RC5_32_12_16_OFB = new Cipher(Native.EVP_rc5_32_12_16_ofb(), false);
#endif

        /// <summary>
        /// AES 128bits Electronic Codebook Mode
        /// </summary>
        public static Cipher AES_128_ECB = new Cipher(NativeMethods.EVP_aes_128_ecb(), false);

        /// <summary>
        /// AES 128bits Cipher-block Chaining Mode
        /// </summary>
        public static Cipher AES_128_CBC = new Cipher(NativeMethods.EVP_aes_128_cbc(), false);

        /// <summary>
        /// AES 128bits Cipher Feedback 1 Mode
        /// </summary>
        public static Cipher AES_128_CFB1 = new Cipher(NativeMethods.EVP_aes_128_cfb1(), false);

        /// <summary>
        /// AES 128bits Cipher Feedback 8 Mode
        /// </summary>
        public static Cipher AES_128_CFB8 = new Cipher(NativeMethods.EVP_aes_128_cfb8(), false);

        /// <summary>
        /// AES 128bits Cipher Feedback 128 Mode
        /// </summary>
        public static Cipher AES_128_CFB128 = new Cipher(NativeMethods.EVP_aes_128_cfb128(), false);

        /// <summary>
        /// AES 128bits Output Feedback Mode
        /// </summary>
        public static Cipher AES_128_OFB = new Cipher(NativeMethods.EVP_aes_128_ofb(), false);

        /// <summary>
        /// AES 128bits Counter Mode
        /// </summary>
        public static Cipher AES_128_CTR = new Cipher(NativeMethods.EVP_aes_128_ctr(), false);

        /// <summary>
        /// AES 128bits Counter with CBC-MAC Mode
        /// </summary>
        public static Cipher AES_128_CCM = new Cipher(NativeMethods.EVP_aes_128_ccm(), false);

        /// <summary>
        /// AES 128bits Galois/Counter Mode
        /// </summary>
        public static Cipher AES_128_GCM = new Cipher(NativeMethods.EVP_aes_128_gcm(), false);

        /// <summary>
        /// AES 128bits XEX-based Tweaked-codebook Mode with Ciphertext Stealing
        /// </summary>
        public static Cipher AES_128_XTS = new Cipher(NativeMethods.EVP_aes_128_xts(), false);

        /// <summary>
        /// AES 128bits Key Wrapping
        /// </summary>
        public static Cipher AES_128_Wrap = new Cipher(NativeMethods.EVP_aes_128_wrap(), false);

        /// <summary>
        /// AES 128bits Key Wrapping with Padding
        /// </summary>
        public static Cipher AES_128_Wrap_Pad = new Cipher(NativeMethods.EVP_aes_128_wrap_pad(), false);

        /// <summary>
        /// AES 128bits Offset Codebook Mode
        /// </summary>
        public static Cipher AES_128_OCB = new Cipher(NativeMethods.EVP_aes_128_ocb(), false);

        /// <summary>
        /// AES 192bits Electronic Codebook Mode
        /// </summary>
        public static Cipher AES_192_ECB = new Cipher(NativeMethods.EVP_aes_192_ecb(), false);

        /// <summary>
        /// AES 192bits Cipher-block Chaining Mode
        /// </summary>
        public static Cipher AES_192_CBC = new Cipher(NativeMethods.EVP_aes_192_cbc(), false);

        /// <summary>
        /// AES 192bits Cipher Feedback 1 Mode
        /// </summary>
        public static Cipher AES_192_CFB1 = new Cipher(NativeMethods.EVP_aes_192_cfb1(), false);

        /// <summary>
        /// AES 192bits Cipher Feedback 8 Mode
        /// </summary>
        public static Cipher AES_192_CFB8 = new Cipher(NativeMethods.EVP_aes_192_cfb8(), false);

        /// <summary>
        /// AES 192bits Cipher Feedback 128 Mode
        /// </summary>
        public static Cipher AES_192_CFB128 = new Cipher(NativeMethods.EVP_aes_192_cfb128(), false);

        /// <summary>
        /// AES 192bits Output Feedback Mode
        /// </summary>
        public static Cipher AES_192_OFB = new Cipher(NativeMethods.EVP_aes_192_ofb(), false);

        /// <summary>
        /// AES 192bits Counter Mode
        /// </summary>
        public static Cipher AES_192_CTR = new Cipher(NativeMethods.EVP_aes_192_ctr(), false);

        /// <summary>
        /// AES 192bits Counter with CBC-MAC Mode
        /// </summary>
        public static Cipher AES_192_CCM = new Cipher(NativeMethods.EVP_aes_192_ccm(), false);

        /// <summary>
        /// AES 192bits Galois/Counter Mode
        /// </summary>
        public static Cipher AES_192_GCM = new Cipher(NativeMethods.EVP_aes_192_gcm(), false);

        /// <summary>
        /// AES 192bits Key Wrapping
        /// </summary>
        public static Cipher AES_192_Wrap = new Cipher(NativeMethods.EVP_aes_192_wrap(), false);

        /// <summary>
        /// AES 192bits Key Wrapping with Padding
        /// </summary>
        public static Cipher AES_192_Wrap_Pad = new Cipher(NativeMethods.EVP_aes_192_wrap_pad(), false);

        /// <summary>
        /// AES 192bits Offset Codebook Mode
        /// </summary>
        public static Cipher AES_192_OCB = new Cipher(NativeMethods.EVP_aes_192_ocb(), false);

        /// <summary>
        /// AES 256bits Electronic Codebook Mode
        /// </summary>
        public static Cipher AES_256_ECB = new Cipher(NativeMethods.EVP_aes_256_ecb(), false);

        /// <summary>
        /// AES 256bits Cipher-block Chaining Mode
        /// </summary>
        public static Cipher AES_256_CBC = new Cipher(NativeMethods.EVP_aes_256_cbc(), false);

        /// <summary>
        /// AES 256bits Cipher Feedback 1 Mode
        /// </summary>
        public static Cipher AES_256_CFB1 = new Cipher(NativeMethods.EVP_aes_256_cfb1(), false);

        /// <summary>
        /// AES 256bits Cipher Feedback 8 Mode
        /// </summary>
        public static Cipher AES_256_CFB8 = new Cipher(NativeMethods.EVP_aes_256_cfb8(), false);

        /// <summary>
        /// AES 256bits Cipher Feedback 128 Mode
        /// </summary>
        public static Cipher AES_256_CFB128 = new Cipher(NativeMethods.EVP_aes_256_cfb128(), false);

        /// <summary>
        /// AES 256bits Output Feedback Mode
        /// </summary>
        public static Cipher AES_256_OFB = new Cipher(NativeMethods.EVP_aes_256_ofb(), false);

        /// <summary>
        /// AES 256bits Counter Mode
        /// </summary>
        public static Cipher AES_256_CTR = new Cipher(NativeMethods.EVP_aes_256_ctr(), false);

        /// <summary>
        /// AES 256bits Counter with CBC-MAC Mode
        /// </summary>
        public static Cipher AES_256_CCM = new Cipher(NativeMethods.EVP_aes_256_ccm(), false);

        /// <summary>
        /// AES 256bits Galois/Counter Mode
        /// </summary>
        public static Cipher AES_256_GCM = new Cipher(NativeMethods.EVP_aes_256_gcm(), false);

        /// <summary>
        /// AES 256bits XEX-based Tweaked-codebook Mode with Ciphertext Stealing
        /// </summary>
        public static Cipher AES_256_XTS = new Cipher(NativeMethods.EVP_aes_256_xts(), false);

        /// <summary>
        /// AES 256bits Key Wrapping
        /// </summary>
        public static Cipher AES_256_Wrap = new Cipher(NativeMethods.EVP_aes_256_wrap(), false);

        /// <summary>
        /// AES 256bits Key Wrapping with Padding
        /// </summary>
        public static Cipher AES_256_Wrap_Pad = new Cipher(NativeMethods.EVP_aes_256_wrap_pad(), false);

        /// <summary>
        /// AES 256bits Offset Codebook Mode
        /// </summary>
        public static Cipher AES_256_OCB = new Cipher(NativeMethods.EVP_aes_256_ocb(), false);

        #endregion

        #region Properties

        /// <summary>
        /// Returns the key_len field
        /// </summary>
        public int KeyLength {
            get { return NativeMethods.EVP_CIPHER_key_length(ptr); }
        }

        /// <summary>
        /// Returns the iv_len field
        /// </summary>
        public int IVLength {
            get { return NativeMethods.EVP_CIPHER_iv_length(ptr); }
        }

        /// <summary>
        /// Returns the block_size field
        /// </summary>
        public int BlockSize {
            get { return NativeMethods.EVP_CIPHER_block_size(ptr); }
        }

        /// <summary>
        /// Returns the flags field
        /// </summary>
        public EVP_CIPH Flags {
            get { return (EVP_CIPH)NativeMethods.EVP_CIPHER_flags(ptr); }
        }

        public EVP_CIPH Mode {
            get {
                return (Flags & EVP_CIPH.MODE);
            }
        }

        /// <summary>
        /// Returns the long name for the nid field using OBJ_nid2ln()
        /// </summary>
        public string LongName {
            get { return NativeMethods.StaticString(NativeMethods.OBJ_nid2ln(NativeMethods.EVP_CIPHER_nid(ptr))); }
        }

        /// <summary>
        /// Returns the name for the nid field using OBJ_nid2sn()
        /// </summary>
        public string Name {
            get { return NativeMethods.StaticString(NativeMethods.OBJ_nid2sn(NativeMethods.EVP_CIPHER_nid(ptr))); }
        }

        /// <summary>
        /// Returns EVP_CIPHER_type()
        /// </summary>
        public int Type {
            get { return NativeMethods.EVP_CIPHER_type(ptr); }
        }

        /// <summary>
        /// Returns the long name for the type using OBJ_nid2ln()
        /// </summary>
        public string TypeName {
            get { return NativeMethods.StaticString(NativeMethods.OBJ_nid2ln(Type)); }
        }
        #endregion
    }
    #endregion

    /// <summary>
    /// Simple struct to encapsulate common parameters for crypto functions
    /// </summary>
    public struct Envelope
    {
        /// <summary>
        /// The key for a crypto operation
        /// </summary>
        public byte[][] Keys;

        /// <summary>
        /// The IV (Initialization Vector)
        /// </summary>
        public byte[] IV;

        /// <summary>
        /// The payload (contains plaintext or ciphertext)
        /// </summary>
        public byte[] Data;
    }

    /// <summary>
    /// Wraps the EVP_CIPHER_CTX object.
    /// </summary>
    public class CipherContext : Base
    {
        /// <summary>
        /// Calls EVP_CIPHER_CTX_new() and initializes the buffer using EVP_CIPHER_CTX_reset()
        /// </summary>
        /// <param name="cipher"></param>
        public CipherContext(Cipher cipher)
            : base(NativeMethods.EVP_CIPHER_CTX_new(), true)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_CIPHER_CTX_reset(ptr));
            this.Cipher = cipher;
        }

        /// <summary>
        /// Returns the cipher's LongName
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            bio.Write("CipherContext: " + Cipher.LongName);
        }

        #region Methods

        /// <summary>
        /// Calls EVP_OpenInit() and EVP_OpenFinal()
        /// </summary>
        /// <param name="input"></param>
        /// <param name="ekey"></param>
        /// <param name="iv"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public byte[] Open(byte[] input, byte[] ekey, byte[] iv, CryptoKey pkey)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_OpenInit(
                ptr, Cipher.Handle, ekey, ekey.Length, iv, pkey.Handle));

            var memory = new MemoryStream();
            var output = new byte[input.Length + Cipher.BlockSize];
            int len;

            NativeMethods.ExpectSuccess(NativeMethods.EVP_DecryptUpdate(ptr, output, out len, input, input.Length));
            memory.Write(output, 0, len);

            NativeMethods.ExpectSuccess(NativeMethods.EVP_OpenFinal(ptr, output, out len));
            memory.Write(output, 0, len);

            return memory.ToArray();
        }

        /// <summary>
        /// Calls EVP_SealInit() and EVP_SealFinal()
        /// </summary>
        /// <param name="pkeys"></param>
        /// <param name="input"></param>
        /// <returns></returns>
        public Envelope Seal(CryptoKey[] pkeys, byte[] input)
        {
            var env = new Envelope();

            var ptrs = new IntPtr[pkeys.Length];

            try {
                env.Keys = new byte[pkeys.Length][];
                var pubkeys = new IntPtr[pkeys.Length];
                var ekeylens = new int[pkeys.Length];

                for (var i = 0; i < pkeys.Length; i++) {
                    ptrs[i] = Marshal.AllocHGlobal(pkeys[i].Size);
                    pubkeys[i] = pkeys[i].Handle;
                }

                if (Cipher.IVLength > 0) {
                    env.IV = new byte[Cipher.IVLength];
                }

                NativeMethods.ExpectSuccess(NativeMethods.EVP_SealInit(
                    ptr, Cipher.Handle, ptrs, ekeylens, env.IV, pubkeys, pubkeys.Length));

                for (var i = 0; i < pkeys.Length; i++) {
                    env.Keys[i] = new byte[ekeylens[i]];
                    Marshal.Copy(ptrs[i], env.Keys[i], 0, ekeylens[i]);
                }

                var memory = new MemoryStream();
                var output = new byte[input.Length + Cipher.BlockSize];

                int len;
                NativeMethods.ExpectSuccess(NativeMethods.EVP_EncryptUpdate(ptr, output, out len, input, input.Length));
                memory.Write(output, 0, len);

                NativeMethods.ExpectSuccess(NativeMethods.EVP_SealFinal(ptr, output, out len));
                memory.Write(output, 0, len);

                env.Data = memory.ToArray();

                return env;
            } finally {
                foreach (var ptr in ptrs) {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }

        /// <summary>
        /// Encrypts or decrypts the specified payload.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="doEncrypt"></param>
        /// <returns></returns>
        public byte[] Crypt(byte[] input, byte[] key, byte[] iv, bool doEncrypt)
        {
            return Crypt(input, key, iv, doEncrypt, -1);
        }

        private byte[] SetupKey(byte[] key)
        {
            if (key == null) {
                key = new byte[Cipher.KeyLength];
                key.Initialize();
                return key;
            }

            if (Cipher.KeyLength == key.Length) {
                return key;
            }

            byte[] real_key = new byte[Cipher.KeyLength];
            real_key.Initialize();
            Buffer.BlockCopy(key, 0, real_key, 0, Math.Min(key.Length, real_key.Length));

            return real_key;
        }

        private byte[] SetupIV(byte[] iv)
        {
            if (Cipher.IVLength > iv.Length) {
                var ret = new byte[Cipher.IVLength];
                ret.Initialize();
                Buffer.BlockCopy(iv, 0, ret, 0, iv.Length);

                return ret;
            }

            return iv;
        }

        /// <summary>
        /// Calls EVP_CipherInit_ex(), EVP_CipherUpdate(), and EVP_CipherFinal_ex()
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="doEncrypt"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] Crypt(byte[] input, byte[] key, byte[] iv, bool doEncrypt, int padding)
        {
            var enc = doEncrypt ? 1 : 0;

            var total = Math.Max(input.Length, Cipher.BlockSize);
            var real_key = SetupKey(key);
            var real_iv = SetupIV(iv);

            var buf = new byte[total];
            var memory = new MemoryStream(total);

            NativeMethods.ExpectSuccess(NativeMethods.EVP_CipherInit_ex(
                ptr, Cipher.Handle, IntPtr.Zero, null, null, enc));

            NativeMethods.ExpectSuccess(NativeMethods.EVP_CIPHER_CTX_set_key_length(ptr, real_key.Length));

            if (IsStream) {
                for (int i = 0; i < Math.Min(real_key.Length, iv.Length); i++) {
                    real_key[i] ^= iv[i];
                }

                NativeMethods.ExpectSuccess(NativeMethods.EVP_CipherInit_ex(
                    ptr, Cipher.Handle, IntPtr.Zero, real_key, null, enc));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.EVP_CipherInit_ex(
                    ptr, Cipher.Handle, IntPtr.Zero, real_key, real_iv, enc));
            }

            if (padding >= 0)
                NativeMethods.ExpectSuccess(NativeMethods.EVP_CIPHER_CTX_set_padding(ptr, padding));

            var len = 0;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_CipherUpdate(ptr, buf, out len, input, input.Length));

            memory.Write(buf, 0, len);

            len = buf.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_CipherFinal_ex(ptr, buf, ref len));

            memory.Write(buf, 0, len);

            return memory.ToArray();
        }

        /// <summary>
        /// Encrypts the specified plaintext
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] input, byte[] key, byte[] iv)
        {
            return Crypt(input, key, iv, true);
        }

        /// <summary>
        /// Decrypts the specified ciphertext
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] input, byte[] key, byte[] iv)
        {
            return Crypt(input, key, iv, false);
        }

        /// <summary>
        /// Encrypts the specified plaintext
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] input, byte[] key, byte[] iv, int padding)
        {
            return Crypt(input, key, iv, true, padding);
        }

        /// <summary>
        /// Decrypts the specified ciphertext
        /// </summary>
        /// <param name="input"></param>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] input, byte[] key, byte[] iv, int padding)
        {
            return Crypt(input, key, iv, false, padding);
        }

        /// <summary>
        /// Calls EVP_BytesToKey
        /// </summary>
        /// <param name="md"></param>
        /// <param name="salt"></param>
        /// <param name="data"></param>
        /// <param name="count"></param>
        /// <param name="iv"></param>
        /// <returns></returns>
        public byte[] BytesToKey(MessageDigest md, byte[] salt, byte[] data, int count, out byte[] iv)
        {
            var keylen = Cipher.KeyLength;
            if (keylen == 0) {
                keylen = 8;
            }
            var key = new byte[keylen];

            var ivlen = Cipher.IVLength;
            if (ivlen == 0) {
                ivlen = 8;
            }
            iv = new byte[ivlen];

            NativeMethods.ExpectSuccess(NativeMethods.EVP_BytesToKey(
                Cipher.Handle,
                md.Handle,
                salt,
                data,
                data.Length,
                count,
                key,
                iv));
            return key;
        }

        #endregion

        #region Properties
        /// <summary>
        /// Returns the EVP_CIPHER for this context.
        /// </summary>
        public Cipher Cipher {
            get;
            private set;
        }

        /// <summary>
        /// Returns if EVP_CIPH_STREAM_CIPHER is set in flags
        /// </summary>
        public bool IsStream {
            get { return Cipher.Mode == EVP_CIPH.STREAM_CIPHER; }
        }
        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls EVP_CIPHER_CTX_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.EVP_CIPHER_CTX_free(ptr);
        }

        #endregion
    }
}
