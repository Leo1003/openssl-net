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
    /// Wraps ECDSA_SIG_st
    /// </summary>
    public class DSASignature : Base
    {
        #region Initialization
        internal DSASignature(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls ECDSA_SIG_new()
        /// </summary>
        public DSASignature()
            : base(NativeMethods.ExpectNonNull(NativeMethods.ECDSA_SIG_new()), true)
        {
        }
        #endregion

        #region Properties

        /// <summary>
        /// Returns R
        /// </summary>
        public BigNumber R {
            get {
                IntPtr rptr = NativeMethods.ECDSA_SIG_get0_r(Handle);
                if (rptr == IntPtr.Zero) {
                    return null;
                }
                return new BigNumber(rptr, false);
            }
        }

        /// <summary>
        /// Returns S
        /// </summary>
        public BigNumber S {
            get {
                IntPtr sptr = NativeMethods.ECDSA_SIG_get0_s(Handle);
                if (sptr == IntPtr.Zero) {
                    return null;
                }
                return new BigNumber(sptr, false);
            }
        }
        #endregion

        #region Methods
        #endregion

        #region Overrides
        /// <summary>
        /// Calls ECDSA_SIG_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.ECDSA_SIG_free(Handle);
        }
        #endregion
    }
}

