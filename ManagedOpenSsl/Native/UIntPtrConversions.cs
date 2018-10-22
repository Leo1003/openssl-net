using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Native
{
    public static class UIntPtrConversions
    {
        public static int ToInt32(this UIntPtr val)
        {
            return Convert.ToInt32(val.ToUInt32());
        }
        public static long ToInt64(this UIntPtr val)
        {
            return Convert.ToInt64(val.ToUInt64());
        }
        public static IntPtr ToIntPtr(this UIntPtr val)
        {
#if _WIN32
            return checked((IntPtr)val.ToUInt32());
#else
            return checked((IntPtr)val.ToUInt64());
#endif
        }
    }
}
