// Copyright (c) 2012 Frank Laub
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

namespace OpenSSL.Crypto.EC
{
    /// <summary>
    /// Wraps EC_KEY
    /// </summary>
    public class Key : BaseReference
    {
        /// <summary>
        /// Compute key handler.
        /// </summary>
        public delegate byte[] ComputeKeyHandler(byte[] msg);

        #region Initialization

        internal Key(IntPtr ptr, bool owner) : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls EC_KEY_new()
        /// </summary>
        public Key() : base(NativeMethods.ExpectNonNull(NativeMethods.EC_KEY_new()), true)
        {
        }

        /// <summary>
        /// Calls EC_KEY_new_by_curve_name()
        /// </summary>
        /// <returns>The curve name.</returns>
        /// <param name="obj">Object.</param>
        public static Key FromCurveName(Asn1Object obj)
        {
            return new Key(NativeMethods.ExpectNonNull(NativeMethods.EC_KEY_new_by_curve_name(obj.NID)), true);
        }

        #endregion

        #region Properties

        /// <summary>
        /// Calls ECDSA_size()
        /// </summary>
        /// <value>The size.</value>
        public int Size {
            get { return NativeMethods.ECDSA_size(ptr); }
        }

        /// <summary>
        /// EC_KEY_get0_group()/Calls EC_KEY_set_group()
        /// </summary>
        /// <value>The group.</value>
        public Group Group {
            get { return new Group(NativeMethods.ExpectNonNull(NativeMethods.EC_KEY_get0_group(ptr)), false); }
            set { NativeMethods.ExpectSuccess(NativeMethods.EC_KEY_set_group(ptr, value.Handle)); }
        }

        /// <summary>
        /// Calls EC_KEY_get0_public_key()
        /// </summary>
        /// <value>The public key.</value>
        public Point PublicKey {
            get {
                return new Point(
                    Group,
                    NativeMethods.ExpectNonNull(NativeMethods.EC_KEY_get0_public_key(ptr)),
                    false);
            }
        }

        /// <summary>
        /// Calls EC_KEY_get0_private_key()
        /// </summary>
        /// <value>The private key.</value>
        public Point PrivateKey {
            get {
                return new Point(
                    this.Group,
                    NativeMethods.ExpectNonNull(NativeMethods.EC_KEY_get0_private_key(ptr)),
                    false);
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Calls EC_KEY_generate_key()
        /// </summary>
        public void GenerateKey()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_KEY_generate_key(ptr));
        }

        /// <summary>
        /// Calls EC_KEY_check_key()
        /// </summary>
        /// <returns><c>true</c>, if key was checked, <c>false</c> otherwise.</returns>
        public bool CheckKey()
        {
            return NativeMethods.ExpectSuccess(NativeMethods.EC_KEY_check_key(ptr)) == 1;
        }

        /// <summary>
        /// Calls ECDSA_do_sign()
        /// </summary>
        /// <param name="digest">Digest.</param>
        public DSASignature Sign(byte[] digest)
        {
            var sig = NativeMethods.ExpectNonNull(NativeMethods.ECDSA_do_sign(digest, digest.Length, ptr));
            return new DSASignature(sig, true);
        }

        /// <summary>
        /// Calls ECDSA_sign()
        /// </summary>
        /// <param name="type">Type.</param>
        /// <param name="digest">Digest.</param>
        /// <param name="sig">Sig.</param>
        public uint Sign(int type, byte[] digest, byte[] sig)
        {
            var siglen = (uint)sig.Length;
            NativeMethods.ExpectSuccess(NativeMethods.ECDSA_sign(type, digest, digest.Length, sig, ref siglen, ptr));

            return siglen;
        }

        /// <summary>
        /// Calls ECDSA_do_verify()
        /// </summary>
        /// <param name="digest">Digest.</param>
        /// <param name="sig">Sig.</param>
        public bool Verify(byte[] digest, DSASignature sig)
        {
            return NativeMethods.ECDSA_do_verify(digest, digest.Length, sig.Handle, ptr) == 1;
        }

        /// <summary>
        /// Calls ECDSA_verify()
        /// </summary>
        /// <param name="type">Type.</param>
        /// <param name="digest">Digest.</param>
        /// <param name="sig">Sig.</param>
        public bool Verify(int type, byte[] digest, byte[] sig)
        {
            return NativeMethods.ECDSA_verify(type, digest, digest.Length, sig, sig.Length, ptr) == 1;
        }

        /// <summary>
        /// Calls ECDH_compute_key()
        /// </summary>
        /// <returns>The key.</returns>
        /// <param name="b">The blue component.</param>
        /// <param name="buf">Buffer.</param>
        /// <param name="kdf">Kdf.</param>
        public int ComputeKey(Key b, byte[] buf, ComputeKeyHandler kdf)
        {
            ComputeKeyThunk thunk = new ComputeKeyThunk(kdf);
            return NativeMethods.ExpectSuccess(
                NativeMethods.ECDH_compute_key(buf, (UIntPtr)buf.Length, b.PublicKey.Handle, ptr, thunk.Wrapper)
            );
        }

        class ComputeKeyThunk
        {
            private ComputeKeyHandler kdf;

            public ComputeKeyThunk(ComputeKeyHandler kdf)
            {
                this.kdf = kdf;
            }

            public IntPtr Wrapper(byte[] pin, UIntPtr inlen, IntPtr pout, ref UIntPtr outlen)
            {
                var result = kdf(pin);
                int len = outlen.ToInt32();

                if (result.Length > len)
                    return IntPtr.Zero;

                Marshal.Copy(result, 0, pout, Math.Min(len, result.Length));
                outlen = (UIntPtr)result.Length;

                return pout;
            }
        }

        #endregion

        #region Overrides

        /// <summary>
        /// This method must be implemented in derived classes.
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.EC_KEY_free(ptr);
        }

        internal override void AddRef()
        {
            NativeMethods.EC_KEY_up_ref(ptr);
        }

        #endregion
    }
}

