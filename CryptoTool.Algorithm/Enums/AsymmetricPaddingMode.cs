using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoTool.Algorithm.Enums
{
    /// <summary>
    /// 非对称加密填充模式枚举
    /// </summary>
    public enum AsymmetricPaddingMode
    {
        /// <summary>
        /// PKCS1填充
        /// </summary>
        PKCS1,
        /// <summary>
        /// OAEP填充
        /// </summary>
        OAEP,
        /// <summary>
        /// PSS填充
        /// </summary>
        PSS,
        /// <summary>
        /// 无填充
        /// </summary>
        None
    }
}
