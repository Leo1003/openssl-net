// Copyright (c) 2009 Frank Laub
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
    /// Wraps the X509_OBJECT: a glorified union
    /// </summary>
    public class X509Object : BaseReference, IStackable
    {
        #region Initialization

        internal X509Object(IStack stack, IntPtr ptr)
            : base(ptr, true)
        {
        }

        public X509Object() : base(NativeMethods.ExpectNonNull(NativeMethods.X509_OBJECT_new()), true)
        {

        }

        #endregion

        #region Properties

        public X509_LookupType Type {
            get {
                return NativeMethods.X509_OBJECT_get_type(ptr);
            }
        }

        /// <summary>
        /// Returns a Certificate if the type is X509_LU_X509
        /// </summary>
        public X509Certificate Certificate {
            get {
                IntPtr retptr = NativeMethods.X509_OBJECT_get0_X509(ptr);
                if (retptr == IntPtr.Zero)
                    return null;
                else
                    return new X509Certificate(retptr, false);
            }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.X509_OBJECT_set1_X509(ptr, value.Handle));
            }
        }

        //TODO: Add support for CRL

        #endregion

        #region Overrides

        /// <summary>
        /// Calls X509_OBJECT_up_ref_count()
        /// </summary>
        internal override void AddRef()
        {
            NativeMethods.X509_OBJECT_up_ref_count(ptr);
        }

        /// <summary>
        /// Calls X509_OBJECT_free_contents()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.X509_OBJECT_free(ptr);
        }

        #endregion
    }
}
