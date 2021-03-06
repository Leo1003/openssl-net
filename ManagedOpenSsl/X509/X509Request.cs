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
using OpenSSL.Crypto;
using OpenSSL.Native;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.X509
{
    /// <summary>
    /// Wraps a X509_REQ object.
    /// </summary>
    public class X509Request : Base
    {
        #region Initialization

        /// <summary>
        /// Calls X509_REQ_new()
        /// </summary>
        public X509Request()
            : base(NativeMethods.ExpectNonNull(NativeMethods.X509_REQ_new()), true)
        {
        }

        internal X509Request(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls X509_REQ_new() and then initializes version, subject, and key.
        /// </summary>
        /// <param name="version"></param>
        /// <param name="subject"></param>
        /// <param name="key"></param>
        public X509Request(int version, X509Name subject, CryptoKey key)
            : this()
        {
            Version = version;
            Subject = subject;
            PublicKey = key;
        }

        /// <summary>
        /// Calls PEM_read_bio_X509_REQ()
        /// </summary>
        /// <param name="bio"></param>
        public X509Request(BIO bio)
            : base(NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_X509_REQ(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)), true)
        {
        }

        /// <summary>
        /// Creates a X509_REQ from a PEM formatted string.
        /// </summary>
        /// <param name="pem"></param>
        public X509Request(string pem)
            : this(new BIO(pem))
        {
        }

        #endregion

        #region Properties

        /// <summary>
        /// Accessor to the version field. The settor calls X509_REQ_set_version().
        /// </summary>
        public int Version {
            get { return NativeMethods.X509_REQ_get_version(Handle); }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_REQ_set_version(Handle, value)); }
        }

        /// <summary>
        /// Accessor to the pubkey field. Uses X509_REQ_get_pubkey() and X509_REQ_set_pubkey()
        /// </summary>
        public CryptoKey PublicKey {
            get { return new CryptoKey(NativeMethods.ExpectNonNull(NativeMethods.X509_REQ_get0_pubkey(Handle)), false); }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_REQ_set_pubkey(Handle, value.Handle)); }
        }

        /// <summary>
        /// Accessor to the subject field. Setter calls X509_REQ_set_subject_name().
        /// </summary>
        public X509Name Subject {
            get { return new X509Name(NativeMethods.X509_REQ_get_subject_name(Handle), false); }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_REQ_set_subject_name(Handle, value.Handle)); }
        }

        /// <summary>
        /// Returns the PEM formatted string for this object.
        /// </summary>
        public string PEM {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    Write(bio);

                    return bio.ReadString();
                }
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Sign this X509Request using the supplied key and digest.
        /// </summary>
        /// <param name="pkey"></param>
        /// <param name="digest"></param>
        public void Sign(CryptoKey pkey, MessageDigest digest)
        {
            if (NativeMethods.X509_REQ_sign(Handle, pkey.Handle, digest.Handle) == 0)
                throw new OpenSslException();
        }

        /// <summary>
        /// Verify this X509Request against the supplied key.
        /// </summary>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public bool Verify(CryptoKey pkey)
        {
            int ret = NativeMethods.X509_REQ_verify(Handle, pkey.Handle);

            if (ret < 0)
                throw new OpenSslException();

            return ret == 1;
        }

        /// <summary>
        /// Digest the specified type and digest.
        /// </summary>
        /// <param name="type">Type.</param>
        /// <param name="digest">Digest.</param>
        public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
        {
            uint len = (uint)digest.Length;
            NativeMethods.ExpectSuccess(NativeMethods.X509_REQ_digest(this.Handle, type, digest, ref len));
            return new ArraySegment<byte>(digest, 0, (int)len);
        }

        /// <summary>
        /// Calls X509_REQ_print()
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.X509_REQ_print(bio.Handle, Handle));
        }

        /// <summary>
        /// Calls PEM_write_bio_X509_REQ()
        /// </summary>
        /// <param name="bio"></param>
        public void Write(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_X509_REQ(bio.Handle, Handle));
        }

        /// <summary>
        /// Converts this request into a certificate using X509_REQ_to_X509().
        /// </summary>
        /// <param name="days"></param>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public X509Certificate CreateCertificate(int days, CryptoKey pkey)
        {
            return new X509Certificate(NativeMethods.ExpectNonNull(NativeMethods.X509_REQ_to_X509(Handle, days, pkey.Handle)), true);
        }

        #endregion

        #region Overrides Members

        /// <summary>
        /// Calls X509_REQ_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.X509_REQ_free(Handle);
        }

        #endregion
    }
}
