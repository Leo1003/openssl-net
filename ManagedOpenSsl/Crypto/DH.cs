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
    /// Encapsulates the native openssl Diffie-Hellman functions (DH_*)
    /// </summary>
    public class DH : BaseReference
    {
        /// <summary>
        /// Constant generator value of 2.
        /// </summary>
        public const int Generator2 = 2;

        /// <summary>
        /// Constant generator value of 5.
        /// </summary>
        public const int Generator5 = 5;

        private const int FlagCacheMont_P = 0x01;

        /// <summary>
        /// Flags for the return value of DH_check().
        /// </summary>
        [Flags]
        public enum CheckCode
        {
            /// <summary>
            ///
            /// </summary>
            CheckP_NotPrime = 1,

            /// <summary>
            ///
            /// </summary>
            CheckP_NotSafePrime = 2,

            /// <summary>
            ///
            /// </summary>
            UnableToCheckGenerator = 4,

            /// <summary>
            ///
            /// </summary>
            NotSuitableGenerator = 8,
        }

        #region Initialization
        internal DH(IntPtr ptr, bool owner) : base(ptr, owner) { }
        /// <summary>
        /// Calls DH_generate_parameters()
        /// </summary>
        /// <param name="primeLen"></param>
        /// <param name="generator"></param>
        public DH(int primeLen, int generator)
            : base(NativeMethods.ExpectNonNull(NativeMethods.DH_new()), true)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DH_generate_parameters_ex(
                ptr,
                primeLen,
                generator,
                IntPtr.Zero)
            );
        }

        /// <summary>
        /// Calls DH_generate_parameters_ex()
        /// </summary>
        /// <param name="primeLen"></param>
        /// <param name="generator"></param>
        /// <param name="callback"></param>
        /// <param name="arg"></param>
        public DH(int primeLen, int generator, BigNumber.GeneratorCallback callback)
            : base(NativeMethods.ExpectNonNull(NativeMethods.DH_new()), true)
        {
            IntPtr cbptr = (callback == null) ? IntPtr.Zero : callback.Handle;
            NativeMethods.ExpectSuccess(NativeMethods.DH_generate_parameters_ex(
                ptr,
                primeLen,
                generator,
                cbptr)
            );
        }

        /// <summary>
        /// Generate parameters with the minimal setting.
        /// </summary>
        public DH()
            : this(3, Generator5)
        {

        }

        /// <summary>
        /// Calls DH_new().
        /// </summary>
        /// <param name="p"></param>
        /// <param name="g"></param>
        public DH(BigNumber p, BigNumber g)
                : base(NativeMethods.ExpectNonNull(NativeMethods.DH_new()), true)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DH_set0_pqg(ptr, NativeMethods.BN_dup(p.Handle), IntPtr.Zero, NativeMethods.BN_dup(g.Handle)));
        }

        /// <summary>
        /// Calls DH_new().
        /// </summary>
        /// <param name="p"></param>
        /// <param name="g"></param>
        /// <param name="pub_key"></param>
        /// <param name="priv_key"></param>
        public DH(BigNumber p, BigNumber g, BigNumber pub_key, BigNumber priv_key)
            : this(p, g)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DH_set0_key(ptr, NativeMethods.BN_dup(pub_key.Handle), NativeMethods.BN_dup(priv_key.Handle)));
        }

        /// <summary>
        /// Factory method that calls FromParametersPEM() to deserialize
        /// a DH object from a PEM-formatted string.
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static DH FromParameters(string pem)
        {
            return FromParametersPEM(new BIO(pem));
        }

        /// <summary>
        /// Factory method that calls PEM_read_bio_DHparams() to deserialize
        /// a DH object from a PEM-formatted string using the BIO interface.
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static DH FromParametersPEM(BIO bio)
        {
            var ptr = NativeMethods.ExpectNonNull(NativeMethods.PEM_read_bio_DHparams(
                bio.Handle, IntPtr.Zero, null, IntPtr.Zero));
            return new DH(ptr, true);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr DH_new_delegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr d2i_DHparams_delegate(out IntPtr a, IntPtr pp, int length);

        private static IntPtr Managed_DH_new()
        {
            return NativeMethods.DH_new();
        }

        private static IntPtr Managed_d2i_DHparams(out IntPtr a, IntPtr pp, int length)
        {
            return NativeMethods.d2i_DHparams(out a, pp, length);
        }
        /// <summary>
        /// Factory method that calls XXX() to deserialize
        /// a DH object from a DER-formatted buffer using the BIO interface.
        /// </summary>
        /// <param name="bio"></param>
        /// <returns></returns>
        public static DH FromParametersDER(BIO bio)
        {
            var dh_new = new DH_new_delegate(Managed_DH_new);
            var d2i_DHparams = new d2i_DHparams_delegate(Managed_d2i_DHparams);
            var dh_new_ptr = Marshal.GetFunctionPointerForDelegate(dh_new);
            var d2i_DHparams_ptr = Marshal.GetFunctionPointerForDelegate(d2i_DHparams);
            var ptr = NativeMethods.ExpectNonNull(NativeMethods.ASN1_d2i_bio(dh_new_ptr, d2i_DHparams_ptr, bio.Handle, IntPtr.Zero));
            var dh = new DH(ptr, true);

            return dh;
        }
        #endregion

        #region Methods
        /// <summary>
        /// Calls DH_generate_key().
        /// </summary>
        public void GenerateKeys()
        {
            NativeMethods.ExpectSuccess(NativeMethods.DH_generate_key(ptr));
        }

        /// <summary>
        /// Calls DH_compute_key().
        /// </summary>
        /// <param name="pubkey"></param>
        /// <returns></returns>
        public byte[] ComputeKey(BigNumber pubkey)
        {
            var len = NativeMethods.DH_size(ptr);
            var key = new byte[len];
            NativeMethods.DH_compute_key(key, pubkey.Handle, ptr);

            return key;
        }

        /// <summary>
        /// Calls PEM_write_bio_DHparams().
        /// </summary>
        /// <param name="bio"></param>
        public void WriteParametersPEM(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.PEM_write_bio_DHparams(bio.Handle, ptr));
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int i2d_DHparams_delegate(IntPtr a, IntPtr pp);

        private int Managed_i2d_DHparams(IntPtr a, IntPtr pp)
        {
            return NativeMethods.i2d_DHparams(a, pp);
        }

        /// <summary>
        /// Calls ASN1_i2d_bio() with the i2d = i2d_DHparams().
        /// </summary>
        /// <param name="bio"></param>
        public void WriteParametersDER(BIO bio)
        {
            var i2d_DHparams = new i2d_DHparams_delegate(Managed_i2d_DHparams);
            var i2d_DHparams_ptr = Marshal.GetFunctionPointerForDelegate(i2d_DHparams);

            NativeMethods.ExpectSuccess(NativeMethods.ASN1_i2d_bio(i2d_DHparams_ptr, bio.Handle, ptr));
            //!!
            /*
			IntPtr hModule = Native.LoadLibrary(Native.DLLNAME);
			IntPtr i2d = Native.GetProcAddress(hModule, "i2d_DHparams");
			Native.FreeLibrary(hModule);

			Native.ExpectSuccess(Native.ASN1_i2d_bio(i2d, bio.Handle, this.ptr));
			*/
        }

        /// <summary>
        /// Calls DHparams_print().
        /// </summary>
        /// <param name="bio"></param>
        public override void Print(BIO bio)
        {
            NativeMethods.ExpectSuccess(NativeMethods.DHparams_print(bio.Handle, ptr));
        }

        /// <summary>
        /// Calls DH_check().
        /// </summary>
        /// <returns></returns>
        public CheckCode Check()
        {
            var codes = 0;
            NativeMethods.ExpectSuccess(NativeMethods.DH_check(ptr, out codes));

            return (CheckCode)codes;
        }
        #endregion

        #region Properties

        /// <summary>
        /// Accessor for the p value.
        /// </summary>
        public BigNumber P {
            get { return new BigNumber(NativeMethods.DH_get0_p(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DH_set0_pqg(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero, IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the g value.
        /// </summary>
        public BigNumber G {
            get { return new BigNumber(NativeMethods.DH_get0_g(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DH_set0_pqg(ptr, IntPtr.Zero, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        /// <summary>
        /// Accessor for the pub_key value.
        /// </summary>
        public BigNumber PublicKey {
            get { return new BigNumber(NativeMethods.DH_get0_pub_key(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DH_set0_key(ptr, NativeMethods.BN_dup(value.Handle), IntPtr.Zero));
            }
        }

        /// <summary>
        /// Accessor for the priv_key value.
        /// </summary>
        public BigNumber PrivateKey {
            get { return new BigNumber(NativeMethods.DH_get0_priv_key(ptr), false); }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.DH_set0_key(ptr, IntPtr.Zero, NativeMethods.BN_dup(value.Handle)));
            }
        }

        /// <summary>
        /// Creates a BIO.MemoryBuffer(), calls WriteParametersPEM() into this buffer,
        /// then returns the buffer as a string.
        /// </summary>
        public string PEM {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    WriteParametersPEM(bio);
                    return bio.ReadString();
                }
            }
        }

        /// <summary>
        /// Creates a BIO.MemoryBuffer(), calls WriteParametersDER() into this buffer,
        /// then returns the buffer.
        /// </summary>
        public byte[] DER {
            get {
                using (var bio = BIO.MemoryBuffer()) {
                    WriteParametersDER(bio);
                    return bio.ReadBytes((int)bio.NumberWritten).Array;
                }
            }
        }

        #endregion

        internal override void AddRef()
        {
            NativeMethods.DH_up_ref(ptr);
        }

        #region IDisposable Members

        /// <summary>
        /// Calls DH_free().
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.DH_free(ptr);
        }

        #endregion
    }
}