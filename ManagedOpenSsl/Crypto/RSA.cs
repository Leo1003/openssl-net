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
using System.Runtime.InteropServices;

namespace OpenSSL.Crypto
{
    /// <summary>
    /// Wraps the RSA_* functions
    /// </summary>
    public class RSA : BaseReference
    {
        #region Enums
        /// <summary>
        /// RSA padding scheme
        /// </summary>
        public enum Padding
        {
            /// <summary>
            /// RSA_PKCS1_PADDING
            /// </summary>
            PKCS1 = 1,
            /// <summary>
            /// RSA_SSLV23_PADDING
            /// </summary>
            SSLv23 = 2,
            /// <summary>
            /// RSA_NO_PADDING
            /// </summary>
            None = 3,
            /// <summary>
            /// RSA_PKCS1_OAEP_PADDING
            /// Optimal Asymmetric Encryption Padding
            /// </summary>
            OAEP = 4,
            /// <summary>
            /// RSA_X931_PADDING
            /// </summary>
            X931 = 5,
        }
        #endregion

        #region Constants
        private const int FlagCacheMont_P = 0x01;
        private const int FlagNoExpConstTime = 0x02;
        private const int FlagNoConstTime = 0x100;
        #endregion

        #region Initialization
        internal RSA(IntPtr ptr, bool owner)
            : base(ptr, owner)
        { }

        /// <summary>
        /// Calls RSA_new()
        /// </summary>
        public RSA()
            : base(NativeMethods.ExpectNonNull(NativeMethods.RSA_new()), true)
        { }

        /// <summary>
        /// Calls PEM_read_bio_RSA_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static RSA FromPublicKey(BIO bio)
        {
            return FromPublicKey(bio, null, null);
        }

        /// <summary>
        /// Calls PEM_read_bio_RSAPrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static RSA FromPrivateKey(BIO bio)
        {
            return FromPrivateKey(bio, null, null);
        }

        /// <summary>
        /// Calls PEM_read_bio_RSA_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        /// <returns></returns>
        public static RSA FromPublicKey(BIO bio, PasswordHandler callback, object arg)
        {
            var thunk = new PasswordThunk(callback, arg);
            var ptr = NativeMethods.PEM_read_bio_RSA_PUBKEY(bio.Handle, IntPtr.Zero, thunk.Callback, IntPtr.Zero);

            return new RSA(NativeMethods.ExpectNonNull(ptr), true);
        }

        /// <summary>
        /// Calls PEM_read_bio_RSAPrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        /// <returns></returns>
        public static RSA FromPrivateKey(BIO bio, PasswordHandler callback, object arg)
        {
            var thunk = new PasswordThunk(callback, arg);
            var ptr = NativeMethods.PEM_read_bio_RSAPrivateKey(bio.Handle, IntPtr.Zero, thunk.Callback, IntPtr.Zero);

            return new RSA(NativeMethods.ExpectNonNull(ptr), true);
        }

        #endregion

        #region Properties
        /// <summary>
        /// Returns RSA_size()
        /// </summary>
        public int Size {
            get { return NativeMethods.ExpectSuccess(NativeMethods.RSA_size(ptr)); }
        }

        /// <summary>
        /// Accessor for the e field
        /// </summary>
        public BigNumber PublicExponent {
            get { return new BigNumber(NativeMethods.RSA_get0_e(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_key(ptr, IntPtr.Zero, NativeMethods.BN_dup(value.Handle), IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the n field
        /// </summary>
        public BigNumber PublicModulus {
            get { return new BigNumber(NativeMethods.RSA_get0_n(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_key(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero, IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the d field
        /// </summary>
        public BigNumber PrivateExponent {
            get { return new BigNumber(NativeMethods.RSA_get0_d(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_key(ptr, IntPtr.Zero, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        /// <summary>
        /// Accessor for the p field
        /// </summary>
        public BigNumber SecretPrimeFactorP {
            get { return new BigNumber(NativeMethods.RSA_get0_p(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_factors(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the q field
        /// </summary>
        public BigNumber SecretPrimeFactorQ {
            get { return new BigNumber(NativeMethods.RSA_get0_q(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_factors(ptr, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        /// <summary>
        /// Accessor for the dmp1 field.
        /// d mod (p-1)
        /// </summary>
        public BigNumber DmodP1 {
            get { return new BigNumber(NativeMethods.RSA_get0_dmp1(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_crt_params(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero, IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the dmq1 field.
        /// d mod (q-1)
        /// </summary>
        public BigNumber DmodQ1 {
            get { return new BigNumber(NativeMethods.RSA_get0_dmq1(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_crt_params(ptr, IntPtr.Zero, NativeMethods.BN_dup(value.Handle), IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the iqmp field.
        /// q^-1 mod p
        /// </summary>
        public BigNumber IQmodP {
            get { return new BigNumber(NativeMethods.RSA_get0_iqmp(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_crt_params(ptr, IntPtr.Zero, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        public int Version {
            get { return NativeMethods.RSA_get_version(ptr); }
        }

        /// <summary>
        /// Returns the public key field as a PEM string
        /// </summary>
        public string PublicKeyAsPEM {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    WritePublicKey(bio);
                    return bio.ReadString();
                }
            }
        }

        /// <summary>
        /// Returns the private key field as a PEM string
        /// </summary>
        public string PrivateKeyAsPEM {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    WritePrivateKey(bio, null, null, null);
                    return bio.ReadString();
                }
            }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Calls RSA_generate_key_ex()
        /// </summary>
        /// <param name="bits"></param>
        /// <param name="e"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        public void GenerateKeys(int bits, BigNumber e, BigNumber.GeneratorCallback callback)
        {
            IntPtr cbptr = (callback == null) ? IntPtr.Zero : callback.Handle;
            NativeMethods.ExpectSuccess(NativeMethods.RSA_generate_key_ex(ptr, bits, e.Handle, cbptr));
        }

        /// <summary>
        /// Calls RSA_public_encrypt()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] PublicEncrypt(byte[] msg, Padding padding)
        {
            var ret = new byte[Size];
            var len = NativeMethods.ExpectSuccess(NativeMethods.RSA_public_encrypt(msg.Length, msg, ret, ptr, (int)padding));

            if (len != ret.Length) {
                var tmp = new byte[len];
                Buffer.BlockCopy(ret, 0, tmp, 0, len);
                return tmp;
            }

            return ret;
        }

        /// <summary>
        /// Calls RSA_private_encrypt()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] PrivateEncrypt(byte[] msg, Padding padding)
        {
            byte[] ret = new byte[this.Size];
            int len = NativeMethods.ExpectSuccess(NativeMethods.RSA_private_encrypt(msg.Length, msg, ret, this.ptr, (int)padding));
            if (len != ret.Length) {
                byte[] tmp = new byte[len];
                Buffer.BlockCopy(ret, 0, tmp, 0, len);
                return tmp;
            }
            return ret;
        }

        /// <summary>
        /// Calls RSA_public_decrypt()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] PublicDecrypt(byte[] msg, Padding padding)
        {
            var ret = new byte[Size];
            var len = NativeMethods.ExpectSuccess(NativeMethods.RSA_public_decrypt(msg.Length, msg, ret, ptr, (int)padding));

            if (len != ret.Length) {
                var tmp = new byte[len];
                Buffer.BlockCopy(ret, 0, tmp, 0, len);
                return tmp;
            }

            return ret;
        }

        /// <summary>
        /// Calls RSA_private_decrypt()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] PrivateDecrypt(byte[] msg, Padding padding)
        {
            var ret = new byte[this.Size];
            var len = NativeMethods.ExpectSuccess(NativeMethods.RSA_private_decrypt(msg.Length, msg, ret, ptr, (int)padding));

            if (len != ret.Length) {
                var tmp = new byte[len];
                Buffer.BlockCopy(ret, 0, tmp, 0, len);
                return tmp;
            }

            return ret;
        }

        /// <summary>
        /// Calls PEM_write_bio_RSA_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        public void WritePublicKey(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_RSA_PUBKEY(bio.Handle, ptr));
        }

        /// <summary>
        /// Calls PEM_write_bio_RSAPrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="enc"></param>
        /// <param name="passwd"></param>
        /// <param name="arg"></param>
        public void WritePrivateKey(BIO bio, Cipher enc, PasswordHandler passwd, object arg)
        {
            PasswordThunk thunk = new PasswordThunk(passwd, arg);
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_RSAPrivateKey(
                bio.Handle,
                this.ptr,
                enc == null ? IntPtr.Zero : enc.Handle,
                null,
                0,
                thunk.Callback,
                IntPtr.Zero));
        }

        /// <summary>
        /// Set RSA public keys
        /// </summary>
        /// <param name="n">Public Modulus</param>
        /// <param name="e">Public Exponent</param>
        public void SetKey(BigNumber n, BigNumber e)
        {
            NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_key(ptr, NativeMethods.BN_dup(n.Handle), NativeMethods.BN_dup(e.Handle), IntPtr.Zero));
        }

        /// <summary>
        /// Set RSA public & private keys
        /// </summary>
        /// <param name="n">Public Modulus</param>
        /// <param name="e">Public Exponent</param>
        /// <param name="d">Private Exponent</param>
        public void SetKey(BigNumber n, BigNumber e, BigNumber d)
        {
            NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_key(ptr, NativeMethods.BN_dup(n.Handle), NativeMethods.BN_dup(e.Handle), NativeMethods.BN_dup(d.Handle)));
        }

        /// <summary>
        /// Set prime factors
        /// </summary>
        /// <param name="p">Factor P</param>
        /// <param name="q">Factor Q</param>
        public void SetFactors(BigNumber p, BigNumber q)
        {
            NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_factors(ptr, NativeMethods.BN_dup(p.Handle), NativeMethods.BN_dup(q.Handle)));
        }

        /// <summary>
        /// Set key params
        /// </summary>
        /// <param name="dmp1">D mod (P - 1)</param>
        /// <param name="dmq1">D mod (Q - 1)</param>
        /// <param name="iqmp">(Q ^ -1) mod P</param>
        public void SetCrtParams(BigNumber dmp1, BigNumber dmq1, BigNumber iqmp)
        {
            NativeMethods.ExpectSuccess(NativeMethods.RSA_set0_crt_params(ptr, NativeMethods.BN_dup(dmp1.Handle), NativeMethods.BN_dup(dmq1.Handle), NativeMethods.BN_dup(iqmp.Handle)));
        }

        /// <summary>
        /// Returns RSA_check_key()
        /// </summary>
        /// <returns></returns>
        public bool Check()
        {
            var ret = NativeMethods.ExpectSuccess(NativeMethods.RSA_check_key(ptr));
            return ret == 1;
        }

        /// <summary>
        /// Calls RSA_print()
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.RSA_print(bio.Handle, ptr, 0));
        }

        #endregion

        #region IDisposable Members

        /// <summary>
        /// Calls RSA_free()
        /// </summary>
        protected override void OnDispose()
        {
            NativeMethods.RSA_free(ptr);
        }

        #endregion

        internal override void AddRef()
        {
            NativeMethods.RSA_up_ref(ptr);
        }
    }
}
