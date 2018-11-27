// Copyright (c) 2006-2009 Frank Laub
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
using System.Reflection;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
    /// <summary>
    /// Base class for all openssl wrapped objects.
    /// Contains the raw unmanaged pointer and has a Handle property to get access to it.
    /// Also overloads the ToString() method with a BIO print.
    /// </summary>
    public abstract class Base : IDisposable
    {
        /// <summary>
        /// Constructor which takes the raw unmanaged pointer.
        /// This is the only way to construct this object and all derived types.
        /// </summary>
        /// <param name="ptr"></param>
        /// <param name="takeOwnership"></param>
        protected Base(IntPtr ptr, bool takeOwnership)
        {
            this.Handle = ptr;
            owner = takeOwnership;
            if (this.Handle != IntPtr.Zero) {
                OnNewHandle(this.Handle);
            }
        }

        /// <summary>
        /// This finalizer just calls Dispose().
        /// </summary>
        ~Base()
        {
            Dispose(false);
        }

        /// <summary>
        /// This method is used by the ToString() implementation. A great number of
        /// openssl objects support printing, so this is a convenience method.
        /// Derived types should override this method and not ToString().
        /// </summary>
        /// <param name="bio">The BIO stream object to print into</param>
        public virtual void Print(BIO bio)
        {
        }

        /// <summary>
        /// Override of ToString() which uses Print() into a BIO memory buffer.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            try {
                if (Handle == IntPtr.Zero)
                    return "(null)";

                using (var bio = BIO.MemoryBuffer()) {
                    Print(bio);
                    return bio.ReadString();
                }
            } catch (Exception) {
                return "<exception>";
            }
        }

        /// <summary>
        /// This method must be implemented in derived classes.
        /// </summary>
        protected abstract void ReleaseHandle();

        /// <summary>
        /// Do nothing in the base class.
        /// </summary>
        /// <param name="ptr"></param>
        internal virtual void OnNewHandle(IntPtr ptr)
        {
        }

        #region IDisposable Members

        /// <summary>
        /// Implementation of the IDisposable interface.
        /// If the native pointer is not null, we haven't been disposed, and we are the owner,
        /// then call the virtual OnDispose() method.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (isDisposed) {
                return;
            }

            if (owner && Handle != IntPtr.Zero) {
                ReleaseHandle();
            }

            Handle = IntPtr.Zero;
            isDisposed = true;
        }

        #endregion

        /// <summary>
        /// gets/sets whether the object owns the Native pointer
        /// </summary>
        public virtual bool IsOwner {
            get { return owner; }
            internal set { owner = value; }
        }

        /// <summary>
        /// Access to the raw unmanaged pointer.
        /// </summary>
        public virtual IntPtr Handle {
            get;
            protected set;
        }

        /// <summary>
        /// If this object is the owner, then call the appropriate native free function.
        /// </summary>
        protected bool owner = false;

        /// <summary>
        /// This is to prevent double-deletion issues.
        /// </summary>
        protected bool isDisposed = false;
    }

    /// <summary>
    /// Helper type that handles the AddRef() method.
    /// </summary>
    public abstract class BaseReference : Base
    {
        internal BaseReference(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
        }

        internal abstract void AddRef();
    }
}
