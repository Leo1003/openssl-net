﻿// Copyright (c) 2009 Frank Laub
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

using OpenSSL.Native;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
    /// <summary>
    /// Wraps ASN1_STRING_*
    /// </summary>
    public class Asn1String : Base, IComparable<Asn1String>
    {
        #region Initialization
        /// <summary>
        /// Calls ASN1_STRING_type_new()
        /// </summary>
        public Asn1String()
            : base(NativeMethods.ASN1_STRING_type_new(NativeMethods.V_ASN1_OCTET_STRING), true)
        {
        }

        /// <summary>
        /// Wrap existing native pointer
        /// </summary>
        /// <param name="ptr"></param>
        /// <param name="takeOwnership"></param>
        internal Asn1String(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
        }

        /// <summary>
        /// Calls ASN1_STRING_set()
        /// </summary>
        /// <param name="data"></param>
        public Asn1String(byte[] data)
            : this()
        {
            NativeMethods.ExpectSuccess(NativeMethods.ASN1_STRING_set(Handle, data, data.Length));
        }
        #endregion

        #region Properties
        /// <summary>
        /// Returns ASN1_STRING_length()
        /// </summary>
        public int Length {
            get { return NativeMethods.ASN1_STRING_length(Handle); }
        }

        /// <summary>
        /// Returns ASN1_STRING_data()
        /// </summary>
        public byte[] Data {
            get {
                var pData = NativeMethods.ASN1_STRING_data(Handle);
                var ret = new byte[Length];

                Marshal.Copy(pData, ret, 0, ret.Length);

                return ret;
            }
        }
        #endregion

        #region Overrides

        /// <summary>
        /// Calls ASN1_STRING_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.ASN1_STRING_free(Handle);
        }

        #endregion

        #region IComparable<Asn1String> Members

        /// <summary>
        /// Returns ASN1_STRING_cmp()
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public int CompareTo(Asn1String other)
        {
            return NativeMethods.ASN1_STRING_cmp(Handle, other.Handle);
        }

        #endregion
    }
}
