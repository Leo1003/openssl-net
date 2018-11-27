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
    public struct Curve
    {
        public BigNumber p;
        public BigNumber a;
        public BigNumber b;
    }
    /// <summary>
    ///
    /// </summary>
    public class Group : Base, IEquatable<Group>
    {
        #region Initialization
        internal Group(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls EC_GROUP_new()
        /// </summary>
        /// <param name="method"></param>
        public Group(Method method)
            : base(NativeMethods.ExpectNonNull(NativeMethods.EC_GROUP_new(method.Handle)), true)
        {
        }

        public Group(Group src)
            : base(NativeMethods.ExpectNonNull(NativeMethods.EC_GROUP_dup(src.Handle)), true)
        {
        }

        /// <summary>
        /// Calls EC_GROUP_new_by_curve_name()
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static Group FromCurveName(Asn1Object obj)
        {
            return new Group(NativeMethods.ExpectNonNull(NativeMethods.EC_GROUP_new_by_curve_name(obj.NID)), true);
        }

        public static Group NewCurveGFp(Curve args)
        {
            IntPtr p = NativeMethods.ExpectNonNull(NativeMethods.EC_GROUP_new_curve_GFp(args.p.Handle, args.a.Handle, args.b.Handle, IntPtr.Zero));
            return new Group(p, true);
        }

        public static Group NewCurveGF2m(Curve args)
        {
            IntPtr p = NativeMethods.ExpectNonNull(NativeMethods.EC_GROUP_new_curve_GF2m(args.p.Handle, args.a.Handle, args.b.Handle, IntPtr.Zero));
            return new Group(p, true);
        }
        #endregion

        #region Properties
        public BigNumber Cofactor {
            get {
                return new BigNumber(NativeMethods.EC_GROUP_get0_cofactor(Handle), false);
            }
        }

        public int CurveNID {
            get {
                return NativeMethods.EC_GROUP_get_curve_name(Handle);
            }
            set {
                NativeMethods.EC_GROUP_set_curve_name(Handle, value);
            }
        }

        /// <summary>
        /// Calls EC_GROUP_get_degree()
        /// </summary>
        public int Degree {
            get { return NativeMethods.EC_GROUP_get_degree(Handle); }
        }

        public Point Generator {
            get {
                IntPtr ret = NativeMethods.EC_GROUP_get0_generator(Handle);
                if (ret == IntPtr.Zero) {
                    return null;
                } else {
                    return new Point(this, ret, false);
                }
            }
        }

        public BigNumber Order {
            get {
                return new BigNumber(NativeMethods.EC_GROUP_get0_order(Handle), false);
            }
        }
        public Curve Curve {
            get {
                Curve ret = new Curve();
                NativeMethods.ExpectSuccess(NativeMethods.EC_GROUP_get_curve(Handle, ret.p.Handle, ret.a.Handle, ret.b.Handle, IntPtr.Zero));
                return ret;
            }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.EC_GROUP_set_curve(Handle, value.p.Handle, value.a.Handle, value.b.Handle, IntPtr.Zero));
            }
        }

        public PointConversionForm ConversionForm {
            get {
                return NativeMethods.EC_GROUP_get_point_conversion_form(Handle);
            }
            set {
                NativeMethods.EC_GROUP_set_point_conversion_form(Handle, value);
            }
        }

        public byte[] Seed {
            get {
                ulong len = NativeMethods.EC_GROUP_get_seed_len(Handle).ToUInt64();
                byte[] ret = new byte[len];
                IntPtr p = NativeMethods.EC_GROUP_get0_seed(Handle);
                Marshal.Copy(p, ret, 0, (int)len);
                return ret;
            }
            set {
                NativeMethods.ExpectSuccess(NativeMethods.EC_GROUP_set_seed(Handle, value, (UIntPtr)value.Length).ToUInt64());
            }
        }

        /// <summary>
        /// Calls EC_GROUP_method_of()
        /// </summary>
        public Method Method {
            get { return new Method(NativeMethods.EC_GROUP_method_of(Handle), false); }
        }

        public bool Isvalid {
            get {
                return NativeMethods.EC_GROUP_check(Handle, IntPtr.Zero) != 0;
            }
        }

        public bool IsvalidDiscriminant {
            get {
                return NativeMethods.EC_GROUP_check_discriminant(Handle, IntPtr.Zero) != 0;
            }
        }

        /// <summary>
        /// Whether to clear the data when disposed
        /// </summary>
        public bool ClearFree {
            get;
            set;
        }
        #endregion

        #region Methods
        public void SetGenerator(Point generator, BigNumber order, BigNumber cofactor)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_GROUP_set_generator(Handle, generator.Handle, order.Handle, cofactor.Handle));
        }

        public void CopyTo(Group to)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_GROUP_copy(to.Handle, Handle));
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Calls EC_GROUP_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            if (ClearFree) {
                NativeMethods.EC_GROUP_clear_free(Handle);
            } else {
                NativeMethods.EC_GROUP_free(Handle);
            }
        }

        public bool Equals(Group other)
        {
            int ret = NativeMethods.EC_GROUP_cmp(Handle, other.Handle, IntPtr.Zero);
            if (ret < 0) {
                throw new OpenSslException();
            }
            return (ret == 0);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as Group);
        }
        #endregion
    }
}

