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

using OpenSSL.Native;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Reflection;

namespace OpenSSL.Core
{
    /// <summary>
    /// The Stack class can only contain objects marked with this interface.
    /// </summary>
    public interface IStackable
    {
        IntPtr GetPushHandle();
    }

    /// <summary>
    /// Encapsulates the sk_* functions
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class Stack<T> : Base, IList<T>
        where T : Base, IStackable
    {
        #region Initialization
        internal Stack(IntPtr ptr, bool owner)
            : base(ptr, owner)
        {
        }

        /// <summary>
        /// Calls sk_new_null()
        /// </summary>
        public Stack()
            : base(NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_new_null()), true)
        {
        }

        #endregion

        #region Methods

        /// <summary>
        /// Calls sk_shift()
        /// </summary>
        /// <returns></returns>
        public T Shift()
        {
            IntPtr ptr = NativeMethods.OPENSSL_sk_shift(this.ptr);
            return CreateInstance(ptr, true);
        }

        public Stack<T> GetCopy()
        {
            return GetCopy(true);
        }

        internal Stack<T> GetCopy(bool takeOwnership)
        {
            return new Stack<T>(NativeMethods.ExpectNonNull(
                NativeMethods.OPENSSL_sk_deep_copy(ptr, CopyPointer, FreePointer)
            ), takeOwnership);
        }

        #endregion

        #region Enumerator
        class Enumerator : IEnumerator<T>
        {
            private Stack<T> parent;
            private int index = -1;
            public Enumerator(Stack<T> parent)
            {
                this.parent = parent;
            }

            #region IEnumerator<T> Members

            public T Current {
                get {
                    if (index < 0 || index >= parent.Count)
                        throw new InvalidOperationException();

                    var ptr = NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_value(parent.Handle, index));

                    // Create a new item
                    T item = parent.CreateInstance(ptr, false);

                    // return it
                    return item;
                }
            }

            #endregion

            #region IDisposable Members
            public void Dispose()
            {
            }
            #endregion

            #region IEnumerator Members

            object IEnumerator.Current {
                get { return Current; }
            }

            public bool MoveNext()
            {
                index++;
                return (index < parent.Count);
            }

            public void Reset()
            {
                index = -1;
            }

            #endregion
        }
        #endregion

        #region Overrides
        /// <summary>
        /// Calls sk_free()
        /// </summary>
        protected override void ReleaseHandle()
        {
            NativeMethods.OPENSSL_sk_pop_free(ptr, FreePointer);
        }

        #endregion

        #region IList<T> Members

        /// <summary>
        /// Returns sk_find()
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public int IndexOf(T item)
        {
            return NativeMethods.OPENSSL_sk_find(ptr, item.Handle);
        }

        /// <summary>
        /// Calls sk_insert()
        /// </summary>
        /// <param name="index"></param>
        /// <param name="item"></param>
        public void Insert(int index, T item)
        {
            // Insert the item into the stack
            NativeMethods.ExpectSuccess(NativeMethods.OPENSSL_sk_insert(ptr, item.GetPushHandle(), index));
        }

        /// <summary>
        /// Calls sk_delete()
        /// </summary>
        /// <param name="index"></param>
        public void RemoveAt(int index)
        {
            IntPtr old_ptr = NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_delete(ptr, index));
            FreePointer(old_ptr);
        }

        /// <summary>
        /// Indexer that returns sk_value() or calls sk_insert()
        /// </summary>
        /// <param name="index"></param>
        /// <returns></returns>
        public T this[int index] {
            get {
                // Get the native pointer from the stack
                var ptr = NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_value(this.ptr, index));

                // Create a new object
                var item = CreateInstance(ptr, false);

                // Return the managed object
                return item;
            }
            set {
                // Change the item in the stack
                IntPtr old_ptr = NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_value(ptr, index));
                FreePointer(old_ptr);

                IntPtr v_ptr = value.GetPushHandle();
                NativeMethods.ExpectNonNull(NativeMethods.OPENSSL_sk_set(ptr, index, v_ptr));
            }
        }

        #endregion

        #region ICollection<T> Members

        /// <summary>
        /// Calls sk_push()
        /// </summary>
        /// <param name="item"></param>
        public void Add(T item)
        {
            // Add the item to the stack
            if (NativeMethods.OPENSSL_sk_push(ptr, item.GetPushHandle()) <= 0)
                throw new OpenSslException();
        }

        /// <summary>
        /// Clear all items from the stack
        /// </summary>
        public void Clear()
        {
            var value_ptr = NativeMethods.OPENSSL_sk_shift(ptr);

            while (value_ptr != IntPtr.Zero) {
                FreePointer(value_ptr);
                value_ptr = NativeMethods.OPENSSL_sk_shift(ptr);
            }
        }

        /// <summary>
        /// Returns true if the specified item exists in this stack.
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public bool Contains(T item)
        {
            foreach (var element in this) {
                if (element.Equals(item))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Not implemented
        /// </summary>
        /// <param name="array"></param>
        /// <param name="arrayIndex"></param>
        public void CopyTo(T[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns sk_num()
        /// </summary>
        public int Count {
            get {
                if (ptr == IntPtr.Zero) {
                    throw new InvalidOperationException("Invalid stack pointer");
                }
                return NativeMethods.OPENSSL_sk_num(ptr);
            }
        }

        /// <summary>
        /// Returns false.
        /// </summary>
        public bool IsReadOnly {
            get { return false; }
        }

        /// <summary>
        /// Calls sk_delete_ptr()
        /// </summary>
        /// <param name="item"></param>
        /// <returns></returns>
        public bool Remove(T item)
        {
            var ptr = NativeMethods.OPENSSL_sk_delete_ptr(this.ptr, item.Handle);

            if (ptr != IntPtr.Zero) {
                FreePointer(ptr);
                return true;
            }

            return false;
        }

        #endregion

        #region IEnumerable Members

        /// <summary>
        /// Returns an enumerator for this stack
        /// </summary>
        /// <returns></returns>
        public IEnumerator<T> GetEnumerator()
        {
            return new Enumerator(this);
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new Enumerator(this);
        }

        #endregion

        #region Helpers

        private T CreateInstance(IntPtr ptr, bool takeOwnership)
        {
            var args = new object[] {
                ptr,
                takeOwnership
            };

            var flags =
                BindingFlags.NonPublic |
                BindingFlags.Public |
                BindingFlags.Instance;

            var item = (T)Activator.CreateInstance(typeof(T), flags, null, args, null);
            return item;
        }

        void FreePointer(IntPtr p)
        {
            CreateInstance(p, true).Dispose();
        }

        IntPtr CopyPointer(IntPtr p)
        {
            return CreateInstance(p, false).GetPushHandle();
        }

        #endregion
    }
}
