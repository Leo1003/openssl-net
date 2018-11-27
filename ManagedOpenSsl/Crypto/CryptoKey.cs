// Copyright (c) 2006-2012 Frank Laub
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

namespace OpenSSL.Crypto
{
    /// <summary>
    /// Wraps the native OpenSSL EVP_PKEY object
    /// </summary>
    public class CryptoKey : BaseReference
    {
        /// <summary>
        /// Set of types that this CryptoKey can be.
        /// </summary>
        public enum KeyType
        {
            /// <summary>
            /// undefined
            /// </summary>
            None = 0,
            /// <summary>
            /// rsaEncryption
            /// </summary>
            RSA = 6,
            /// <summary>
            /// rsa
            /// </summary>
            RSA2 = 19,
            /// <summary>
            /// rsassaPss
            /// </summary>
            RSA_PSS = 912,
            /// <summary>
            /// dsaEncryption
            /// </summary>
            DSA = 116,
            /// <summary>
            /// dsaEncryption-old
            /// </summary>
            DSA1 = 67,
            /// <summary>
            /// dsaWithSHA
            /// </summary>
            DSA2 = 66,
            /// <summary>
            /// dsaWithSHA1
            /// </summary>
            DSA3 = 113,
            /// <summary>
            /// dsaWithSHA1-old
            /// </summary>
            DSA4 = 70,
            /// <summary>
            /// dhKeyAgreement
            /// </summary>
            DH = 28,
            /// <summary>
            /// X9.42 DH
            /// </summary>
            DHX = 920,
            /// <summary>
            /// ecPublicKey
            /// </summary>
            EC = 408,
            /// <summary>
            /// sm2
            /// </summary>
            SM2 = 1172,
            /// <summary>
            /// hmac
            /// </summary>
            HMAC = 855,
            /// <summary>
            /// cmac
            /// </summary>
            CMAC = 894,
            /// <summary>
            /// scrypt
            /// </summary>
            SCRYPT = 973,
            /// <summary>
            /// tls1-prf
            /// </summary>
            TLS1_PRF = 1021,
            /// <summary>
            /// hkdf
            /// </summary>
            HKDF = 1036,
            /// <summary>
            /// poly1305
            /// </summary>
            POLY1305 = 1061,
            /// <summary>
            /// siphash
            /// </summary>
            SIPHASH = 1062,
            /// <summary>
            /// X25519
            /// </summary>
            X25519 = 1034,
            /// <summary>
            /// ED25519
            /// </summary>
            ED25519 = 1087,
            /// <summary>
            /// X448
            /// </summary>
            X448 = 1035,
            /// <summary>
            /// ED448
            /// </summary>
            ED448 = 1088,
        }

        #region Initialization

        internal CryptoKey(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls EVP_PKEY_new()
        /// </summary>
        public CryptoKey()
            : base(NativeMethods.ExpectNonNull(NativeMethods.EVP_PKEY_new()), true)
        {
        }

        private CryptoKey(CryptoKey other)
            : base(other.Handle, true)
        {
            AddRef();
        }

        /// <summary>
        /// Returns a copy of this object.
        /// </summary>
        /// <returns></returns>
        public CryptoKey CopyRef()
        {
            return new CryptoKey(this);
        }

        /// <summary>
        /// Calls PEM_read_bio_PUBKEY()
        /// </summary>
        /// <param name="pem"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static CryptoKey FromPublicKey(string pem, string password)
        {
            using (var bio = new BIO(pem)) {
                return FromPublicKey(bio, password);
            }
        }

        /// <summary>
        /// Calls PEM_read_bio_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static CryptoKey FromPublicKey(BIO bio, string password)
        {
            var callback = new PasswordCallback(password);
            return FromPublicKey(bio, callback.OnPassword, null);
        }

        /// <summary>
        /// Calls PEM_read_bio_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="handler"></param>
        /// <param name="arg"></param>
        /// <returns></returns>
        public static CryptoKey FromPublicKey(BIO bio, PasswordHandler handler, object arg)
        {
            var thunk = new PasswordThunk(handler, arg);
            var ptr = NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_PUBKEY(
                          bio.Handle,
                          IntPtr.Zero,
                          thunk.Callback,
                          IntPtr.Zero
                      ));

            return new CryptoKey(ptr, true);
        }

        /// <summary>
        /// Calls PEM_read_bio_PrivateKey()
        /// </summary>
        /// <param name="pem"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static CryptoKey FromPrivateKey(string pem, string password)
        {
            using (var bio = new BIO(pem)) {
                return FromPrivateKey(bio, password);
            }
        }

        /// <summary>
        /// Calls PEM_read_bio_PrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="passwd"></param>
        /// <returns></returns>
        public static CryptoKey FromPrivateKey(BIO bio, string passwd)
        {
            var callback = new PasswordCallback(passwd);
            return FromPrivateKey(bio, callback.OnPassword, null);
        }

        /// <summary>
        /// Calls PEM_read_bio_PrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="handler"></param>
        /// <param name="arg"></param>
        /// <returns></returns>
        public static CryptoKey FromPrivateKey(BIO bio, PasswordHandler handler, object arg)
        {
            var thunk = new PasswordThunk(handler, arg);
            var ptr = NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_PrivateKey(
                          bio.Handle,
                          IntPtr.Zero,
                          thunk.Callback,
                          IntPtr.Zero
                      ));

            return new CryptoKey(ptr, true);
        }

        /// <summary>
        /// Calls EVP_PKEY_set1_DSA()
        /// </summary>
        /// <param name="dsa"></param>
        public CryptoKey(DSA dsa)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_set1_DSA(Handle, dsa.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_set1_RSA()
        /// </summary>
        /// <param name="rsa"></param>
        public CryptoKey(RSA rsa)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_set1_RSA(Handle, rsa.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_set1_EC()
        /// </summary>
        /// <param name="ec"></param>
        public CryptoKey(EC.Key ec)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_set1_EC_KEY(Handle, ec.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_set1_DH()
        /// </summary>
        /// <param name="dh"></param>
        public CryptoKey(DH dh)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_set1_DH(Handle, dh.Handle));
        }

        #endregion

        #region Properties

        /// <summary>
        /// Returns EVP_PKEY_type()
        /// </summary>
        public KeyType Type {
            get { return (KeyType)NativeMethods.EVP_PKEY_base_id(Handle); }
        }

        /// <summary>
        /// Returns EVP_PKEY_bits()
        /// </summary>
        public int Bits {
            get { return NativeMethods.EVP_PKEY_bits(Handle); }
        }

        /// <summary>
        /// Returns EVP_PKEY_size()
        /// </summary>
        public int Size {
            get { return NativeMethods.EVP_PKEY_size(Handle); }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Calls EVP_PKEY_assign()
        /// </summary>
        /// <param name="key">Key.</param>
        public void Assign(RSA key)
        {
            key.AddRef();
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_assign(Handle, (int)KeyType.RSA, key.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_assign()
        /// </summary>
        /// <param name="key">Key.</param>
        public void Assign(DSA key)
        {
            key.AddRef();
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_assign(Handle, (int)KeyType.DSA, key.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_assign()
        /// </summary>
        /// <param name="key">Key.</param>
        public void Assign(DH key)
        {
            key.AddRef();
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_assign(Handle, (int)KeyType.DH, key.Handle));
        }

        /// <summary>
        /// Calls EVP_PKEY_assign()
        /// </summary>
        /// <param name="key">Key.</param>
        public void Assign(EC.Key key)
        {
            key.AddRef();
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_assign(Handle, (int)KeyType.EC, key.Handle));
        }

        /// <summary>
        /// Returns EVP_PKEY_get1_DSA()
        /// </summary>
        /// <returns></returns>
        public DSA GetDSA()
        {
            if (Type != KeyType.DSA)
                throw new InvalidOperationException();

            return new DSA(NativeMethods.ExpectNonNull(NativeMethods.EVP_PKEY_get1_DSA(Handle)), true);
        }

        /// <summary>
        /// Returns EVP_PKEY_get1_DH()
        /// </summary>
        /// <returns></returns>
        public DH GetDH()
        {
            if (Type != KeyType.DH)
                throw new InvalidOperationException();

            return new DH(NativeMethods.ExpectNonNull(NativeMethods.EVP_PKEY_get1_DH(Handle)), true);
        }

        /// <summary>
        /// Returns EVP_PKEY_get1_RSA()
        /// </summary>
        /// <returns></returns>
        public RSA GetRSA()
        {
            if (Type != KeyType.RSA)
                throw new InvalidOperationException();

            return new RSA(NativeMethods.ExpectNonNull(NativeMethods.EVP_PKEY_get1_RSA(Handle)), true);
        }

        /// <summary>
        /// Returns EVP_PKEY_get1_EC()
        /// </summary>
        /// <returns></returns>
        public EC.Key GetEC()
        {
            if (Type != KeyType.EC)
                throw new InvalidOperationException();

            return new EC.Key(NativeMethods.ExpectNonNull(NativeMethods.EVP_PKEY_get1_EC_KEY(Handle)), true);
        }


        /// <summary>
        /// Calls PEM_write_bio_PKCS8PrivateKey
        /// </summary>
        /// <param name="bp"></param>
        /// <param name="cipher"></param>
        /// <param name="password"></param>
        public void WritePrivateKey(BIO bp, Cipher cipher, string password)
        {
            PasswordCallback callback = new PasswordCallback(password);
            WritePrivateKey(bp, cipher, callback.OnPassword, null);
        }

        /// <summary>
        /// Calls PEM_write_bio_PKCS8PrivateKey
        /// </summary>
        /// <param name="bp"></param>
        /// <param name="cipher"></param>
        /// <param name="handler"></param>
        /// <param name="arg"></param>
        public void WritePrivateKey(BIO bp, Cipher cipher, PasswordHandler handler, object arg)
        {
            var thunk = new PasswordThunk(handler, null);
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_PKCS8PrivateKey(bp.Handle, Handle, cipher.Handle, IntPtr.Zero, 0, thunk.Callback, IntPtr.Zero));
        }

        #endregion

        #region Overrides

        /// <summary>
        /// Calls EVP_PKEY_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.EVP_PKEY_free(Handle);
        }

        /// <summary>
        /// Returns CompareTo(obj)
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            var rhs = obj as CryptoKey;

            if (rhs == null)
                return false;

            return NativeMethods.EVP_PKEY_cmp(Handle, rhs.Handle) == 1;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        /// <summary>
        /// Calls appropriate Print() based on the type.
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            switch (Type) {
                case KeyType.RSA:
                    GetRSA().Print(bio);
                    break;
                case KeyType.DSA:
                    GetDSA().Print(bio);
                    break;
                case KeyType.EC:
                    break;
                case KeyType.DH:
                    GetDH().Print(bio);
                    break;
            }
        }

        internal override void AddRef()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EVP_PKEY_up_ref(Handle));
        }

        #endregion
    }
}
