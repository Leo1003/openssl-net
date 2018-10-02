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
    /// Wraps the DSA_* functions
    /// </summary>
    public class DSA : BaseReference
    {
        private int counter = 0;
        private IntPtr h;
        private BigNumber.GeneratorThunk thunk = null;

        #region Initialization

        internal DSA(IntPtr ptr, bool owner) : base(ptr, owner) { }

        /// <summary>
        /// Calls DSA_new() then DSA_generate_parameters_ex()
        /// </summary>
        public DSA(bool generateKeys)
            : base(NativeMethods.ExpectNonNull(NativeMethods.DSA_new()), true)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DSA_generate_parameters_ex(
                ptr,
                512,
                null, 0,
                out counter,
                out h,
                null)
            );

            if (generateKeys)
                GenerateKeys();
        }

        /// <summary>
        /// Calls DSA_new() then DSA_generate_parameters_ex()
        /// </summary>
        /// <param name="bits"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        public DSA(int bits, BigNumber.GeneratorHandler callback, object arg)
            : base(NativeMethods.ExpectNonNull(NativeMethods.DSA_new()), true)
        {
            thunk = new BigNumber.GeneratorThunk(callback, arg);

            NativeMethods.ExpectSuccess(NativeMethods.DSA_generate_parameters_ex(
                ptr,
                bits,
                null, 0,
                out counter,
                out h,
                thunk.CallbackStruct)
            );
        }

        /// <summary>
        /// Calls DSA_new() then DSA_generate_parameters_ex()
        /// </summary>
        /// <param name="bits"></param>
        /// <param name="seed"></param>
        /// <param name="counter"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        public DSA(int bits, byte[] seed, int counter, BigNumber.GeneratorHandler callback, object arg)
            : base(NativeMethods.ExpectNonNull(NativeMethods.DSA_new()), true)
        {
            this.counter = counter;
            thunk = new BigNumber.GeneratorThunk(callback, arg);

            NativeMethods.ExpectSuccess(NativeMethods.DSA_generate_parameters_ex(
                ptr,
                bits,
                seed, seed.Length,
                out this.counter,
                out h,
                thunk.CallbackStruct)
            );
        }

        /// <summary>
        /// Returns PEM_read_bio_DSA_PUBKEY()
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static DSA FromPublicKey(string pem)
        {
            return FromPublicKey(new BIO(pem));
        }

        /// <summary>
        /// Returns PEM_read_bio_DSA_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static DSA FromPublicKey(BIO bio)
        {
            return new DSA(NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_DSA_PUBKEY(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)), true);
        }

        /// <summary>
        /// Returns PEM_read_bio_DSAPrivateKey()
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static DSA FromPrivateKey(string pem)
        {
            return FromPrivateKey(new BIO(pem));
        }

        /// <summary>
        /// Returns PEM_read_bio_DSAPrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static DSA FromPrivateKey(BIO bio)
        {
            return new DSA(NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_DSAPrivateKey(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)), true);
        }

        #endregion

        #region Properties

        /// <summary>
        /// Returns the p field
        /// </summary>
        public BigNumber P {
            get { return new BigNumber(NativeMethods.DSA_get0_p(ptr), false); }
        }

        /// <summary>
        /// Returns the q field
        /// </summary>
        public BigNumber Q {
            get { return new BigNumber(NativeMethods.DSA_get0_q(ptr), false); }
        }

        /// <summary>
        /// Returns the g field
        /// </summary>
        public BigNumber G {
            get { return new BigNumber(NativeMethods.DSA_get0_g(ptr), false); }
        }

        /// <summary>
        /// Returns DSA_size()
        /// </summary>
        public int Size {
            get { return NativeMethods.ExpectSuccess(NativeMethods.DSA_size(ptr)); }
        }

        /// <summary>
        /// Returns the pub_key field
        /// </summary>
        public BigNumber PublicKey {
            get { return new BigNumber(NativeMethods.DSA_get0_pub_key(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DSA_set0_key(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero));
            }
        }

        /// <summary>
        /// Returns the priv_key field
        /// </summary>
        public BigNumber PrivateKey {
            get {
                var pKey = NativeMethods.DSA_get0_priv_key(ptr);
                if (pKey == IntPtr.Zero)
                    return null;
                return new BigNumber(pKey, false);
            }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DSA_set0_key(ptr, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        /// <summary>
        /// Returns the pub_key field as a PEM string
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
        /// Returns the priv_key field as a PEM string
        /// </summary>
        public string PrivateKeyAsPEM {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    WritePrivateKey(bio, null, null, null);

                    return bio.ReadString();
                }
            }
        }

        /// <summary>
        /// Returns the counter
        /// </summary>
        public int Counter {
            get { return counter; }
        }

        /// <summary>
        /// Returns the h value
        /// </summary>
        public IntPtr H {
            get { return h; }
        }
        #endregion

        #region Methods
        /// <summary>
        /// Calls DSA_generate_key()
        /// </summary>
        public void GenerateKeys()
        {
            NativeMethods.ExpectSuccess(NativeMethods.DSA_generate_key(ptr));
        }

        /// <summary>
        /// Set public key and private key
        /// </summary>
        /// <param name="pub_key"></param>
        /// <param name="priv_key"></param>
        public void SetKey(BigNumber pub_key, BigNumber priv_key)
        {
            if (priv_key == null) {
                NativeMethods.ExpectSuccess(NativeMethods.DSA_set0_key(ptr, NativeMethods.BN_dup(pub_key.Handle), IntPtr.Zero));
            } else {
                NativeMethods.ExpectSuccess(NativeMethods.DSA_set0_key(ptr, NativeMethods.BN_dup(pub_key.Handle), NativeMethods.BN_dup(priv_key.Handle)));
            }
        }

        /// <summary>
        /// Returns DSA_sign()
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public byte[] Sign(byte[] msg)
        {
            var sig = new byte[Size];
            uint siglen;
            NativeMethods.ExpectSuccess(NativeMethods.DSA_sign(0, msg, msg.Length, sig, out siglen, ptr));

            if (sig.Length != siglen) {
                var ret = new byte[siglen];
                Buffer.BlockCopy(sig, 0, ret, 0, (int)siglen);
                return ret;
            }

            return sig;
        }

        /// <summary>
        /// Returns DSA_verify()
        /// </summary>
        /// <param name="msg"></param>
        /// <param name="sig"></param>
        /// <returns></returns>
        public bool Verify(byte[] msg, byte[] sig)
        {
            return NativeMethods.ExpectSuccess(
                NativeMethods.DSA_verify(0, msg, msg.Length, sig, sig.Length, ptr)
            ) == 1;
        }

        /// <summary>
        /// Calls PEM_write_bio_DSA_PUBKEY()
        /// </summary>
        /// <param name="bio"></param>
        public void WritePublicKey(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_DSA_PUBKEY(bio.Handle, ptr));
        }

        /// <summary>
        /// Calls PEM_write_bio_DSAPrivateKey()
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="enc"></param>
        /// <param name="passwd"></param>
        /// <param name="arg"></param>
        public void WritePrivateKey(BIO bio, Cipher enc, PasswordHandler passwd, object arg)
        {
            var thunk = new PasswordThunk(passwd, arg);

            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_DSAPrivateKey(
                bio.Handle,
                ptr,
                enc == null ? IntPtr.Zero : enc.Handle,
                null,
                0,
                thunk.Callback,
                IntPtr.Zero));
        }

        #endregion

        #region Overrides

        /// <summary>
        /// Calls DSA_print()
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DSA_print(bio.Handle, ptr, 0));
        }

        /// <summary>
        /// Calls DSA_free()
        /// </summary>
        protected override void OnDispose()
        {
            NativeMethods.DSA_free(ptr);
        }

        /// <summary>
        /// If both objects have a private key, those are compared.
        /// Otherwise just the params and public keys are compared.
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            var rhs = obj as DSA;
            if (rhs == null)
                return false;

            var paramsEqual = (
                P == rhs.P &&
                Q == rhs.Q &&
                G == rhs.G
            );

            if (!paramsEqual)
                return false;

            if (PublicKey != rhs.PublicKey)
                return false;

            var lhsPrivateKey = PrivateKey;
            var rhsPrivateKey = rhs.PrivateKey;

            if (lhsPrivateKey == null || rhsPrivateKey == null)
                return true;

            return lhsPrivateKey == rhsPrivateKey;
        }

        /// <summary>
        /// Xor of the params, public key, and optionally the private key
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            var code =
                P.GetHashCode() ^
                Q.GetHashCode() ^
                G.GetHashCode() ^
                PublicKey.GetHashCode();

            if (PrivateKey != null)
                code ^= PrivateKey.GetHashCode();

            return code;
        }

        internal override void AddRef()
        {
            NativeMethods.DSA_up_ref(ptr);
        }

        #endregion
    }
}
