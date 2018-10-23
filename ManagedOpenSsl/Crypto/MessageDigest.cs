// Copyright (c) 2006-2011 Frank Laub
// All rights reserved.
//
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
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Crypto
{
    #region MessageDigest
    /// <summary>
    /// Wraps the EVP_MD object
    /// </summary>
    public class MessageDigest : Base
    {
        /// <summary>
        /// Creates a EVP_MD struct
        /// </summary>
        /// <param name="ptr"></param>
        /// <param name="owner"></param>
        internal MessageDigest(IntPtr ptr, bool owner) : base(ptr, owner)
        {
        }

        /// <summary>
        /// Prints MessageDigest
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            bio.Write("MessageDigest");
        }

        /// <summary>
        /// Not implemented, these objects should never be disposed.
        /// </summary>
        protected override void ReleaseHandle()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Calls EVP_get_digestbyname()
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static MessageDigest CreateByName(string name)
        {
            var buf = Encoding.ASCII.GetBytes(name);
            var ptr = NativeMethods.EVP_get_digestbyname(buf);

            if (ptr == IntPtr.Zero)
                return null;

            return new MessageDigest(ptr, false);
        }

        /// <summary>
        /// Calls OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH)
        /// </summary>
        public static string[] AllNamesSorted {
            get { return new NameCollector(ObjNameType.MD_METH, true).Result.ToArray(); }
        }

        /// <summary>
        /// Calls OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH)
        /// </summary>
        public static string[] AllNames {
            get { return new NameCollector(ObjNameType.MD_METH, false).Result.ToArray(); }
        }

        #region MessageDigests
        /// <summary>
        /// Null
        /// </summary>
        public readonly static MessageDigest Null = new MessageDigest(NativeMethods.EVP_md_null(), false);

        /// <summary>
        /// MD4
        /// </summary>
        public readonly static MessageDigest MD4 = new MessageDigest(NativeMethods.EVP_md4(), false);

        /// <summary>
        /// MD5
        /// </summary>
        public readonly static MessageDigest MD5 = new MessageDigest(NativeMethods.EVP_md5(), false);

        /// <summary>
        /// SHA-1
        /// </summary>
        public readonly static MessageDigest SHA1 = new MessageDigest(NativeMethods.EVP_sha1(), false);

        /// <summary>
        /// SHA-224
        /// </summary>
        public readonly static MessageDigest SHA224 = new MessageDigest(NativeMethods.EVP_sha224(), false);

        /// <summary>
        /// SHA-256
        /// </summary>
        public readonly static MessageDigest SHA256 = new MessageDigest(NativeMethods.EVP_sha256(), false);

        /// <summary>
        /// SHA-384
        /// </summary>
        public readonly static MessageDigest SHA384 = new MessageDigest(NativeMethods.EVP_sha384(), false);

        /// <summary>
        /// SHA-512
        /// </summary>
        public readonly static MessageDigest SHA512 = new MessageDigest(NativeMethods.EVP_sha512(), false);

        /// <summary>
        /// SHA-512/224
        /// </summary>
        public readonly static MessageDigest SHA512_224 = new MessageDigest(NativeMethods.EVP_sha512_224(), false);

        /// <summary>
        /// SHA-512/256
        /// </summary>
        public readonly static MessageDigest SHA512_256 = new MessageDigest(NativeMethods.EVP_sha512_256(), false);

        /// <summary>
        /// SHA3-224
        /// </summary>
        public readonly static MessageDigest SHA3_224 = new MessageDigest(NativeMethods.EVP_sha3_224(), false);

        /// <summary>
        /// SHA3-256
        /// </summary>
        public readonly static MessageDigest SHA3_256 = new MessageDigest(NativeMethods.EVP_sha3_256(), false);

        /// <summary>
        /// SHA3-384
        /// </summary>
        public readonly static MessageDigest SHA3_384 = new MessageDigest(NativeMethods.EVP_sha3_384(), false);

        /// <summary>
        /// SHA3-512
        /// </summary>
        public readonly static MessageDigest SHA3_512 = new MessageDigest(NativeMethods.EVP_sha3_512(), false);

        /// <summary>
        /// SHAKE128
        /// </summary>
        public readonly static MessageDigest SHAKE128 = new MessageDigest(NativeMethods.EVP_shake128(), false);

        /// <summary>
        /// SHAKE256
        /// </summary>
        public readonly static MessageDigest SHAKE256 = new MessageDigest(NativeMethods.EVP_shake256(), false);

        /// <summary>
        /// EVP_ripemd160()
        /// </summary>
        public readonly static MessageDigest RipeMD160 = new MessageDigest(NativeMethods.EVP_ripemd160(), false);
        #endregion

        #region Properties
        /// <summary>
        /// Returns the block_size field
        /// </summary>
        public int BlockSize {
            get { return NativeMethods.EVP_MD_block_size(ptr); }
        }

        /// <summary>
        /// Returns the md_size field
        /// </summary>
        public int Size {
            get { return NativeMethods.EVP_MD_size(ptr); }
        }

        /// <summary>
        /// Returns the type field using OBJ_nid2ln()
        /// </summary>
        public string LongName {
            get { return NativeMethods.StaticString(NativeMethods.OBJ_nid2ln(NativeMethods.EVP_MD_type(ptr))); }
        }

        /// <summary>
        /// Returns the type field using OBJ_nid2sn()
        /// </summary>
        public string Name {
            get { return NativeMethods.StaticString(NativeMethods.OBJ_nid2sn(NativeMethods.EVP_MD_type(ptr))); }
        }

        #endregion
    }
    #endregion

    /// <summary>
    /// Wraps the EVP_MD_CTX object
    /// </summary>
    public class MessageDigestContext : Base
    {
        private MessageDigest md;

        /// <summary>
        /// Calls BIO_get_md_ctx() then BIO_get_md()
        /// </summary>
        /// <param name="bio"></param>
        public MessageDigestContext(BIO bio)
            : base(NativeMethods.ExpectNonNull(NativeMethods.BIO_get_md_ctx(bio.Handle)), false)
        {
            md = new MessageDigest(NativeMethods.ExpectNonNull(NativeMethods.BIO_get_md(bio.Handle)), false);
        }

        /// <summary>
        /// Calls EVP_MD_CTX_create() then EVP_MD_CTX_init()
        /// </summary>
        /// <param name="md"></param>
        public MessageDigestContext(MessageDigest md)
            : base(NativeMethods.EVP_MD_CTX_new(), true)
        {
            NativeMethods.EVP_MD_CTX_reset(ptr);
            this.md = md;
        }

        /// <summary>
        /// Prints the long name
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            bio.Write("MessageDigestContext: " + md.LongName);
        }

        #region Methods

        /// <summary>
        /// Calls EVP_DigestInit_ex(), EVP_DigestUpdate(), and EVP_DigestFinal_ex()
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public byte[] Digest(byte[] msg)
        {
            var digest = new byte[md.Size];
            var len = (uint)digest.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestInit_ex(ptr, md.Handle, IntPtr.Zero));
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestUpdate(ptr, msg, (UIntPtr)msg.Length));
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestFinal_ex(ptr, digest, ref len));
            return digest;
        }

        /// <summary>
        /// Calls EVP_DigestInit_ex()
        /// </summary>
        public void Init()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestInit_ex(ptr, md.Handle, IntPtr.Zero));
        }

        /// <summary>
        /// Calls EVP_DigestUpdate()
        /// </summary>
        /// <param name="msg"></param>
        public void Update(byte[] msg)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestUpdate(ptr, msg, (UIntPtr)msg.Length));
        }

        /// <summary>
        /// Calls EVP_DigestFinal_ex()
        /// </summary>
        /// <returns></returns>
        public byte[] DigestFinal()
        {
            var digest = new byte[md.Size];
            var len = (uint)digest.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestFinal_ex(ptr, digest, ref len));

            return digest;
        }

        /// <summary>
        /// Calls EVP_SignFinal()
        /// </summary>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public byte[] SignFinal(CryptoKey pkey)
        {
            var sig = new byte[pkey.Size];
            var len = (uint)sig.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_SignFinal(ptr, sig, ref len, pkey.Handle));

            return sig;
        }

        /// <summary>
        /// Calls EVP_VerifyFinal()
        /// </summary>
        /// <param name="sig"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public bool VerifyFinal(byte[] sig, CryptoKey pkey)
        {
            var ret = NativeMethods.ExpectSuccess(NativeMethods.EVP_VerifyFinal(ptr, sig, (uint)sig.Length, pkey.Handle));

            return ret == 1;
        }

        /// <summary>
        /// Calls EVP_DigestInit_ex(), EVP_DigestUpdate(), and EVP_SignFinal()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public byte[] Sign(byte[] msg, CryptoKey pkey)
        {
            var sig = new byte[pkey.Size];
            var len = (uint)sig.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestInit_ex(ptr, md.Handle, IntPtr.Zero));
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestUpdate(ptr, msg, (UIntPtr)msg.Length));
            NativeMethods.ExpectSuccess(NativeMethods.EVP_SignFinal(ptr, sig, ref len, pkey.Handle));

            var ret = new byte[len];
            Buffer.BlockCopy(sig, 0, ret, 0, (int)len);

            return ret;
        }

        /// <summary>
        /// Calls EVP_SignFinal()
        /// </summary>
        /// <param name="md"></param>
        /// <param name="bio"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public static byte[] Sign(MessageDigest md, BIO bio, CryptoKey pkey)
        {
            var bmd = BIO.MessageDigest(md);
            bmd.Push(bio);

            while (true) {
                var bytes = bmd.ReadBytes(1024 * 4);
                if (bytes.Count == 0)
                    break;
            }

            var ctx = new MessageDigestContext(bmd);

            var sig = new byte[pkey.Size];
            var len = (uint)sig.Length;
            NativeMethods.ExpectSuccess(NativeMethods.EVP_SignFinal(ctx.Handle, sig, ref len, pkey.Handle));
            var ret = new byte[len];
            Buffer.BlockCopy(sig, 0, ret, 0, (int)len);

            return ret;
        }

        /// <summary>
        /// Calls EVP_DigestInit_ex(), EVP_DigestUpdate(), and EVP_VerifyFinal()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="sig"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public bool Verify(byte[] msg, byte[] sig, CryptoKey pkey)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestInit_ex(ptr, md.Handle, IntPtr.Zero));
            NativeMethods.ExpectSuccess(NativeMethods.EVP_DigestUpdate(ptr, msg, (UIntPtr)msg.Length));

            var ret = NativeMethods.ExpectSuccess(NativeMethods.EVP_VerifyFinal(ptr, sig, (uint)sig.Length, pkey.Handle));
            return ret == 1;
        }

        /// <summary>
        /// Calls EVP_VerifyFinal()
        /// </summary>
        /// <param name="md"></param>
        /// <param name="bio"></param>
        /// <param name="sig"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public static bool Verify(MessageDigest md, BIO bio, byte[] sig, CryptoKey pkey)
        {
            var bmd = BIO.MessageDigest(md);
            bmd.Push(bio);

            while (true) {
                var bytes = bmd.ReadBytes(1024 * 4);
                if (bytes.Count == 0)
                    break;
            }

            var ctx = new MessageDigestContext(bmd);

            var ret = NativeMethods.ExpectSuccess(NativeMethods.EVP_VerifyFinal(ctx.Handle, sig, (uint)sig.Length, pkey.Handle));
            return ret == 1;
        }

        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls EVP_MD_CTX_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.EVP_MD_CTX_free(ptr);
        }

        #endregion
    }
}
