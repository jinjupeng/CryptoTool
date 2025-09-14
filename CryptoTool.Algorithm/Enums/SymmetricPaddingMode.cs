using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoTool.Algorithm.Enums
{
    /// <summary>
    /// 对称加密填充模式枚举
    /// </summary>
    public enum SymmetricPaddingMode
    {
        /// <summary>
        /// PKCS7填充（推荐）
        /// </summary>
        PKCS7,
        /// <summary>
        /// PKCS5填充
        /// </summary>
        PKCS5,
        /// <summary>
        /// 零填充
        /// </summary>
        Zeros,
        /// <summary>
        /// ISO10126填充
        /// </summary>
        ISO10126,
        /// <summary>
        /// ANSIX923填充
        /// </summary>
        ANSIX923,
        /// <summary>
        /// 无填充
        /// </summary>
        None
    }
}
