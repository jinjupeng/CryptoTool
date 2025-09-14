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
        /// PKCS7填充（推荐）- 最常用的标准填充模式
        /// </summary>
        PKCS7,
        /// <summary>
        /// PKCS5填充 - 与PKCS7类似，但专门用于8字节块大小
        /// </summary>
        PKCS5,
        /// <summary>
        /// 零填充 - 使用零字节填充
        /// </summary>
        Zeros,
        /// <summary>
        /// ISO10126填充 - 使用随机字节填充，最后一字节表示填充长度
        /// </summary>
        ISO10126,
        /// <summary>
        /// ANSIX923填充 - 填充字节为零，最后一字节表示填充长度
        /// </summary>
        ANSIX923,
        /// <summary>
        /// 无填充 - 要求输入数据长度必须是块大小的整数倍
        /// </summary>
        None
    }
}
