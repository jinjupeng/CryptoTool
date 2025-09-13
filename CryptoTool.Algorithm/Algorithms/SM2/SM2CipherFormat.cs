using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoTool.Algorithm.Algorithms.SM2
{
    /// <summary>
    /// SM2密文格式枚举
    /// </summary>
    public enum SM2CipherFormat
    {
        /// <summary>
        /// C1C2C3格式（标准格式）
        /// </summary>
        C1C2C3,
        /// <summary>
        /// C1C3C2格式（国密标准格式）
        /// </summary>
        C1C3C2
    }
}
