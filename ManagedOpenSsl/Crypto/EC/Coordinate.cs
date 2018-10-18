using OpenSSL.Core;
using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL.Crypto.EC
{
    public struct CompressedCoordinate
    {
        public BigNumber X;
        public bool Y;
    }

    public struct AffineCoordinate
    {
        public BigNumber X;
        public BigNumber Y;
    }

    public struct JprojectiveCoordinate
    {
        public BigNumber X;
        public BigNumber Y;
        public BigNumber Z;
    }
}
