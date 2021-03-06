﻿using OpenSSL.Native;
using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Core
{
    public class ThreadLock : Base
    {
        public ThreadLock() : base(NativeMethods.ExpectNonNull(NativeMethods.CRYPTO_THREAD_lock_new()), true)
        {

        }

        public void LockRead()
        {
            NativeMethods.ExpectSuccess(NativeMethods.CRYPTO_THREAD_read_lock(Handle));
        }

        public void LockWrite()
        {
            NativeMethods.ExpectSuccess(NativeMethods.CRYPTO_THREAD_write_lock(Handle));
        }

        public void Unlock()
        {
            NativeMethods.ExpectSuccess(NativeMethods.CRYPTO_THREAD_unlock(Handle));
        }

        protected override void ReleaseHandle()
        {
            NativeMethods.CRYPTO_THREAD_lock_free(Handle);
        }
    }
}
