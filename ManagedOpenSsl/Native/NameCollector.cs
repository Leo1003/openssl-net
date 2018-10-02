using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Native
{
    class NameCollector
    {
        [StructLayout(LayoutKind.Sequential)]
        struct OBJ_NAME
        {
            public int type;
            public int alias;
            public IntPtr name;
            public IntPtr data;
        };

        private List<string> list = new List<string>();

        public List<string> Result { get { return list; } }

        public NameCollector(ObjNameType type, bool isSorted)
        {
            if (isSorted)
                NativeMethods.OBJ_NAME_do_all_sorted((int)type, OnObjectName, IntPtr.Zero);
            else
                NativeMethods.OBJ_NAME_do_all((int)type, OnObjectName, IntPtr.Zero);
        }

        private void OnObjectName(IntPtr ptr, IntPtr arg)
        {
            var name = (OBJ_NAME)Marshal.PtrToStructure(ptr, typeof(OBJ_NAME));
            var str = NativeMethods.PtrToStringAnsi(name.name, false);
            list.Add(str);
        }
    }
}
