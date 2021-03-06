// Copyright (c) 2006-2010 Frank Laub
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
    /// Wraps the X509 object
    /// </summary>
    public class X509Certificate : BaseReference, IComparable<X509Certificate>, IStackable
    {
        #region Initialization

        internal X509Certificate(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        internal X509Certificate(IntPtr ptr, IntPtr pkey)
            : base(ptr, true)
        {
            if (pkey != IntPtr.Zero) {
                privateKey = new CryptoKey(pkey, true);
            }
        }

        private X509Certificate(X509Certificate other)
            : base(other.Handle, true)
        {
            AddRef();
            if (other.privateKey != null) {
                privateKey = other.privateKey.CopyRef();
            }
        }

        /// <summary>
        /// Calls X509_new()
        /// </summary>
        public X509Certificate()
            : base(NativeMethods.ExpectNonNull(NativeMethods.X509_new()), true)
        {
        }

        /// <summary>
        /// Calls PEM_read_bio_X509()
        /// </summary>
        /// <param name="bio"></param>
        public X509Certificate(BIO bio)
            : base(
                NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_X509(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)),
                true)
        {
        }

        /// <summary>
        /// Factory method that returns a X509 using d2i_X509_bio()
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static X509Certificate FromDER(BIO bio)
        {
            IntPtr pX509 = IntPtr.Zero;
            IntPtr ptr = NativeMethods.ExpectNonNull(NativeMethods.d2i_X509_bio(bio.Handle, ref pX509));
            return new X509Certificate(ptr, true);
        }

        /// <summary>
        /// Factory method to create a X509Certificate from a PKCS7 encoded in PEM
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static X509Certificate FromPKCS7_PEM(BIO bio)
        {
            var pkcs7 = PKCS7.FromPEM(bio);
            var chain = pkcs7.Certificates;

            if (chain != null && chain.Count > 0) {
                return new X509Certificate(chain[0].Handle, false);
            } else {
                throw new OpenSslException();
            }
        }

        /// <summary>
        /// Factory method to create a X509Certificate from a PKCS7 encoded in DER
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static X509Certificate FromPKCS7_DER(BIO bio)
        {
            var pkcs7 = PKCS7.FromDER(bio);
            var chain = pkcs7.Certificates;

            if (chain != null && chain.Count > 0) {
                return new X509Certificate(chain[0].Handle, false);
            }

            return null;
        }

        /// <summary>
        /// Factory method to create a X509Certificate from a PKCS12
        /// </summary>
        /// <param name="bio"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static X509Certificate FromPKCS12(BIO bio, string password)
        {
            using (var p12 = new PKCS12(bio, password)) {
                return p12.Certificate;
            }
        }

        /// <summary>
        /// Creates a new X509 certificate
        /// </summary>
        /// <param name="serial"></param>
        /// <param name="subject"></param>
        /// <param name="issuer"></param>
        /// <param name="pubkey"></param>
        /// <param name="start"></param>
        /// <param name="end"></param>
        public X509Certificate(
            int serial,
            X509Name subject,
            X509Name issuer,
            CryptoKey pubkey,
            DateTime start,
            DateTime end)
            : this()
        {
            Version = 2;
            SerialNumber = serial;
            Subject = subject;
            Issuer = issuer;
            PublicKey = pubkey;
            NotBefore = start;
            NotAfter = end;
        }

        #endregion

        #region Properties

        /// <summary>
        /// Uses X509_get_subject_name() and X509_set_issuer_name()
        /// </summary>
        public X509Name Subject {
            get {
                // Get the native pointer for the subject name
                var name_ptr = NativeMethods.ExpectNonNull(NativeMethods.X509_get_subject_name(this.Handle));
                var ret = new X509Name(name_ptr, false);
                // Duplicate the native pointer, as the X509_get_subject_name returns a pointer
                // that is owned by the X509 object

                return ret;
            }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_set_subject_name(this.Handle, value.Handle)); }
        }

        /// <summary>
        /// Uses X509_get_issuer_name() and X509_set_issuer_name()
        /// </summary>
        public X509Name Issuer {
            get {
                var name_ptr = NativeMethods.ExpectNonNull(NativeMethods.X509_get_issuer_name(Handle));
                var name = new X509Name(name_ptr, false);

                return name;
            }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_set_issuer_name(Handle, value.Handle)); }
        }

        /// <summary>
        /// Uses X509_get_serialNumber() and X509_set_serialNumber()
        /// </summary>
        public int SerialNumber {
            get { return Asn1Integer.ToInt32(NativeMethods.X509_get_serialNumber(Handle)); }
            set {
                using (var asnInt = new Asn1Integer(value)) {
                    NativeMethods.ExpectSuccess(NativeMethods.X509_set_serialNumber(Handle, asnInt.Handle));
                }
            }
        }

        /// <summary>
        /// Uses the notBefore field and X509_set_notBefore()
        /// </summary>
        public DateTime NotBefore {
            get { return Asn1DateTime.ToDateTime(NativeMethods.X509_get0_notBefore(Handle)); }
            set {
                using (var asnDateTime = new Asn1DateTime(value)) {
                    NativeMethods.ExpectSuccess(NativeMethods.X509_set1_notBefore(Handle, asnDateTime.Handle));
                }
            }
        }

        /// <summary>
        /// Uses the notAfter field and X509_set_notAfter()
        /// </summary>
        public DateTime NotAfter {
            get { return Asn1DateTime.ToDateTime(NativeMethods.X509_get0_notAfter(Handle)); }
            set {
                using (var asnDateTime = new Asn1DateTime(value)) {
                    NativeMethods.ExpectSuccess(NativeMethods.X509_set1_notAfter(Handle, asnDateTime.Handle));
                }
            }
        }

        /// <summary>
        /// Uses the version field and X509_set_version()
        /// </summary>
        public int Version {
            get { return NativeMethods.X509_get_version(Handle); }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_set_version(Handle, value)); }
        }

        /// <summary>
        /// Uses X509_get_pubkey() and X509_set_pubkey()
        /// </summary>
        public CryptoKey PublicKey {
            get {
                // X509_get_pubkey() will increment the refcount internally
                var key_ptr = NativeMethods.ExpectNonNull(NativeMethods.X509_get_pubkey(Handle));
                return new CryptoKey(key_ptr, true);
            }
            set { NativeMethods.ExpectSuccess(NativeMethods.X509_set_pubkey(Handle, value.Handle)); }
        }

        /// <summary>
        /// Returns whether or not a Private Key is attached to this Certificate
        /// </summary>
        public bool HasPrivateKey {
            get { return privateKey != null; }
        }

        /// <summary>
        /// Gets and Sets the Private Key for this Certificate.
        /// The Private Key MUST match the Public Key.
        /// </summary>
        public CryptoKey PrivateKey {
            get {
                if (privateKey == null)
                    return null;
                return privateKey.CopyRef();
            }
            set {
                if (value == null) {
                    privateKey = null;
                } else {
                    if (CheckPrivateKey(value)) {
                        privateKey = value.CopyRef();
                    } else {
                        throw new ArgumentException("Private key doesn't correspond to the this certificate");
                    }
                }
            }
        }

        /// <summary>
        /// Returns the PEM formatted string of this object
        /// </summary>
        public string PEM {
            get {
                using (BIO bio = BIO.MemoryBuffer()) {
                    this.Write(bio);
                    return bio.ReadString();
                }
            }
        }

        /// <summary>
        /// Returns the DER formatted byte array for this object
        /// </summary>
        public byte[] DER {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    Write_DER(bio);
                    return bio.ReadBytes((int)bio.NumberWritten).Array;
                }
            }
        }

        #endregion

        #region Methods

        /// <summary>
        /// Returns a copy of this object.
        /// </summary>
        /// <returns></returns>
        public X509Certificate CopyRef()
        {
            return new X509Certificate(this);
        }

        /// <summary>
        /// Calls X509_sign()
        /// </summary>
        /// <param name="pkey"></param>
        /// <param name="digest"></param>
        public void Sign(CryptoKey pkey, MessageDigest digest)
        {
            if (NativeMethods.X509_sign(Handle, pkey.Handle, digest.Handle) == 0)
                throw new OpenSslException();
        }

        /// <summary>
        /// Returns X509_check_private_key()
        /// </summary>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public bool CheckPrivateKey(CryptoKey pkey)
        {
            return NativeMethods.X509_check_private_key(Handle, pkey.Handle) == 1;
        }

        /// <summary>
        /// Returns X509_check_trust()
        /// </summary>
        /// <param name="id"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        public bool CheckTrust(int id, int flags)
        {
            return NativeMethods.X509_check_trust(Handle, id, flags) == 1;
        }

        /// <summary>
        /// Returns X509_verify()
        /// </summary>
        /// <param name="pkey"></param>
        /// <returns></returns>
        public bool Verify(CryptoKey pkey)
        {
            var ret = NativeMethods.X509_verify(Handle, pkey.Handle);

            if (ret < 0)
                throw new OpenSslException();

            return ret == 1;
        }

        /// <summary>
        /// Returns X509_digest()
        /// </summary>
        /// <param name="type"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
        {
            var len = (uint)digest.Length;

            NativeMethods.ExpectSuccess(NativeMethods.X509_digest(Handle, type, digest, ref len));

            return new ArraySegment<byte>(digest, 0, (int)len);
        }

        /// <summary>
        /// Returns X509_pubkey_digest()
        /// </summary>
        /// <param name="type"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        public ArraySegment<byte> DigestPublicKey(IntPtr type, byte[] digest)
        {
            var len = (uint)digest.Length;

            NativeMethods.ExpectSuccess(NativeMethods.X509_pubkey_digest(Handle, type, digest, ref len));

            return new ArraySegment<byte>(digest, 0, (int)len);
        }

        /// <summary>
        /// Calls PEM_write_bio_X509()
        /// </summary>
        /// <param name="bio"></param>
        public void Write(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_X509(bio.Handle, Handle));
        }

        /// <summary>
        /// Calls i2d_X509_bio()
        /// </summary>
        /// <param name="bio"></param>
        public void Write_DER(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.i2d_X509_bio(bio.Handle, Handle));
        }

        /// <summary>
        /// Calls X509_print()
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.X509_print(bio.Handle, Handle));
        }

        /// <summary>
        /// Converts a X509 into a request using X509_to_X509_REQ()
        /// </summary>
        /// <param name="pkey"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        public X509Request CreateRequest(CryptoKey pkey, MessageDigest digest)
        {
            return new X509Request(NativeMethods.ExpectNonNull(NativeMethods.X509_to_X509_REQ(Handle, pkey.Handle, digest.Handle)), true);
        }

        /// <summary>
        /// Calls X509_add_ext()
        /// </summary>
        /// <param name="ext"></param>
        public void AddExtension(X509Extension ext)
        {
            NativeMethods.ExpectSuccess(NativeMethods.X509_add_ext(Handle, ext.Handle, -1));
        }

        /// <summary>
        /// Calls X509_add1_ext_i2d()
        /// </summary>
        /// <param name="name"></param>
        /// <param name="value"></param>
        /// <param name="crit"></param>
        /// <param name="flags"></param>
        public void AddExtension(string name, byte[] value, int crit, uint flags)
        {
            NativeMethods.ExpectSuccess(NativeMethods.X509_add1_ext_i2d(Handle, NativeMethods.TextToNID(name), value, crit, flags));
        }

        /// <summary>
        ///
        /// </summary>
        public Core.Stack<X509Extension> Extensions {
            get {
                IntPtr extptr = NativeMethods.X509_get0_extensions(Handle);
                if (extptr == IntPtr.Zero) {
                    return null;
                }
                return new Core.Stack<X509Extension>(extptr, false);
            }
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="sk_ext"></param>
        public void AddExtensions(Core.Stack<X509Extension> sk_ext)
        {
            foreach (var ext in sk_ext) {
                AddExtension(ext);
            }
        }

        #endregion

        #region Overrides

        public IntPtr GetPushHandle()
        {
            AddRef();
            return Handle;
        }

        /// <summary>
        /// Calls X509_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.X509_free(Handle);

            if (privateKey != null) {
                privateKey.Dispose();
                privateKey = null;
            }
        }

        /// <summary>
        /// Compares X509Certificate
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            var rhs = obj as X509Certificate;

            if (rhs == null)
                return false;

            return CompareTo(rhs) == 0;
        }

        /// <summary>
        /// Returns the hash code of the issuer's oneline xor'd with the serial number
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return Issuer.OneLine.GetHashCode() ^ SerialNumber;
        }

        internal override void AddRef()
        {
            NativeMethods.ExpectSuccess(NativeMethods.X509_up_ref(Handle));
        }

        #endregion

        #region IComparable Members

        /// <summary>
        /// Returns X509_cmp()
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(X509Certificate other)
        {
            return NativeMethods.X509_cmp(Handle, other.Handle);
        }

        #endregion

        #region Fields

        private CryptoKey privateKey;

        #endregion
    }
}
