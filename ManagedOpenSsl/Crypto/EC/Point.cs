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

namespace OpenSSL.Crypto.EC
{
    /// <summary>
    /// Wraps EC_POINT
    /// </summary>
    public class Point : Base, IEquatable<Point>
    {
        private Group group;

        #region Initialization
        internal Point(Group group, IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
            this.group = group;
        }

        /// <summary>
        /// Calls EC_POINT_new()
        /// </summary>
        /// <param name="group"></param>
        public Point(Group group)
            : base(NativeMethods.EC_POINT_new(group.Handle), true)
        {
            this.group = group;
        }

        public Point(Point point)
            : base(NativeMethods.ExpectNonNull(NativeMethods.EC_POINT_dup(point.Handle, point.group.Handle)), true)
        {
            this.group = point.group;
        }
        #endregion

        #region Properties
        public bool IsInfinity {
            get {
                return Convert.ToBoolean(NativeMethods.EC_POINT_is_at_infinity(group.Handle, ptr));
            }
        }

        public bool IsOnCurve {
            get {
                int ret = NativeMethods.EC_POINT_is_on_curve(group.Handle, ptr, IntPtr.Zero);
                if (ret < 0) {
                    throw new OpenSslException();
                }
                return Convert.ToBoolean(ret);
            }
        }

        public JprojectiveCoordinate JprojectiveCoordinates_GFp {
            get {
                JprojectiveCoordinate c = new JprojectiveCoordinate();
                NativeMethods.ExpectSuccess(
                    NativeMethods.EC_POINT_get_Jprojective_coordinates_GFp(group.Handle, ptr, c.X.Handle, c.Y.Handle, c.Z.Handle, IntPtr.Zero)
                );
                return c;
            }
            set {
                NativeMethods.ExpectSuccess(
                    NativeMethods.EC_POINT_set_Jprojective_coordinates_GFp(group.Handle, ptr, value.X.Handle, value.Y.Handle, value.Z.Handle, IntPtr.Zero)
                );
            }
        }

        public AffineCoordinate AffineCoordinates {
            get {
                AffineCoordinate c = new AffineCoordinate();
                NativeMethods.ExpectSuccess(
                    NativeMethods.EC_POINT_get_affine_coordinates(group.Handle, ptr, c.X.Handle, c.Y.Handle, IntPtr.Zero)
                );
                return c;
            }
            set {
                NativeMethods.ExpectSuccess(
                    NativeMethods.EC_POINT_set_affine_coordinates(group.Handle, ptr, value.X.Handle, value.Y.Handle, IntPtr.Zero)
                );
            }
        }

        public CompressedCoordinate CompressedCoordinates {
            set {
                NativeMethods.ExpectSuccess(
                    NativeMethods.EC_POINT_set_compressed_coordinates(group.Handle, ptr, value.X.Handle, (value.Y ? 1 : 0), IntPtr.Zero)
                );
            }
        }
        #endregion

        #region Methods
        public static Point Double(Point p)
        {
            Point ret = new Point(p.group);
            NativeMethods.ExpectSuccess(NativeMethods.EC_POINT_dbl(p.group.Handle, ret.Handle, p.Handle, IntPtr.Zero));
            return ret;
        }

        public static Point Multiple(Point p, BigNumber n, BigNumber m)
        {
            Point ret = new Point(p.group);
            NativeMethods.ExpectSuccess(
                NativeMethods.EC_POINT_mul(p.group.Handle, n.Handle, ret.Handle, p.Handle, m.Handle, IntPtr.Zero)
            );
            return ret;
        }

        public void MakeAffine()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_POINT_make_affine(group.Handle, ptr, IntPtr.Zero));
        }

        public void Invert()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_POINT_invert(group.Handle, ptr, IntPtr.Zero));
        }

        public void SetToInfinity()
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_POINT_set_to_infinity(group.Handle, ptr));
        }

        public void CopyTo(Point to)
        {
            NativeMethods.ExpectSuccess(NativeMethods.EC_POINT_copy(to.Handle, ptr));
        }
        #endregion

        #region Operators
        public static Point operator +(Point a, Point b)
        {
            Point ret = new Point(a.group);
            NativeMethods.ExpectSuccess(
                NativeMethods.EC_POINT_add(a.group.Handle, ret.Handle, a.Handle, b.Handle, IntPtr.Zero)
            );
            return ret;
        }

        public static Point operator *(Point a, BigNumber b)
        {
            Point ret = new Point(a.group);
            NativeMethods.ExpectSuccess(
                NativeMethods.EC_POINT_mul(a.group.Handle, IntPtr.Zero, ret.Handle, a.Handle, b.Handle, IntPtr.Zero)
            );
            return ret;
        }

        public static bool operator ==(Point a, Point b)
        {
            return a.Equals(b);
        }

        public static bool operator !=(Point a, Point b)
        {
            return !a.Equals(b);
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Calls EC_POINT_free()
        /// </summary>
        protected override void OnDispose()
        {
            NativeMethods.EC_POINT_free(this.ptr);
        }

        public bool Equals(Point other)
        {
            int ret = NativeMethods.EC_POINT_cmp(group.Handle, ptr, other.Handle, IntPtr.Zero);
            if (ret < 0) {
                throw new OpenSslException();
            }
            return !Convert.ToBoolean(ret);
        }
        #endregion
    }
}

