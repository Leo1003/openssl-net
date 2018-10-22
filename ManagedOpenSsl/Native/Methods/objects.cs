using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Native
{
    internal partial class NativeMethods
    {
        public const int NID_undef = 0;

        public const int OBJ_undef = 0;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void ObjectNameHandler(IntPtr name, IntPtr arg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OBJ_NAME_do_all(int type, ObjectNameHandler fn, IntPtr arg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static void OBJ_NAME_do_all_sorted(int type, ObjectNameHandler fn, IntPtr arg);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static int OBJ_ln2nid(string s);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OBJ_nid2ln(int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OBJ_nid2obj(int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static IntPtr OBJ_nid2sn(int n);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl)]
        public extern static int OBJ_obj2nid(IntPtr o);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static int OBJ_sn2nid(string s);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static int OBJ_txt2nid(string s);

        [DllImport(DLLNAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public extern static IntPtr OBJ_txt2obj(string s, int no_name);
    }
}
