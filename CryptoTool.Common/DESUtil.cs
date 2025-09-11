using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Common;

namespace CryptoTool.Common
{
    /// <summary>
    /// DES对称加密工具类
    /// 提供字符串、文件、流的DES加密解密功能
    /// 支持多种加密模式、填充方式和输出格式
    /// </summary>
    public class DESUtil : BaseCryptoProvider
    {
        #region 属性

        /// <summary>
        /// 算法类型
        /// </summary>
        public override AlgorithmType AlgorithmType => AlgorithmType.DES;

        /// <summary>
        /// 密钥长度（字节）
        /// </summary>
        protected override int KeySize => 8; // 64位

        /// <summary>
        /// 块大小（字节）
        /// </summary>
        protected override int BlockSize => 8; // 64位

        /// <summary>
        /// IV长度（字节）
        /// </summary>
        protected override int IVSize => 8; // 64位

        #endregion


        #region 抽象方法实现

        /// <summary>
        /// 创建加密器
        /// </summary>
        protected override ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CipherMode mode, 
            PaddingMode padding, bool isEncryption)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.Mode = ConvertCipherMode(mode);
                des.Padding = ConvertPaddingMode(padding);

                if (mode != CipherMode.ECB && iv != null)
                    des.IV = iv;

                return isEncryption ? des.CreateEncryptor() : des.CreateDecryptor();
            }
        }

        /// <summary>
        /// 转换加密模式
        /// </summary>
        protected override System.Security.Cryptography.CipherMode ConvertCipherMode(CipherMode mode)
        {
            return mode switch
            {
                CipherMode.ECB => System.Security.Cryptography.CipherMode.ECB,
                CipherMode.CBC => System.Security.Cryptography.CipherMode.CBC,
                CipherMode.CFB => System.Security.Cryptography.CipherMode.CFB,
                CipherMode.OFB => System.Security.Cryptography.CipherMode.OFB,
                _ => System.Security.Cryptography.CipherMode.CBC
            };
        }

        /// <summary>
        /// 转换填充模式
        /// </summary>
        protected override System.Security.Cryptography.PaddingMode ConvertPaddingMode(PaddingMode padding)
        {
            return padding switch
            {
                PaddingMode.PKCS7 => System.Security.Cryptography.PaddingMode.PKCS7,
                PaddingMode.PKCS5 => System.Security.Cryptography.PaddingMode.PKCS7, // .NET中PKCS5等同于PKCS7
                PaddingMode.Zeros => System.Security.Cryptography.PaddingMode.Zeros,
                PaddingMode.None => System.Security.Cryptography.PaddingMode.None,
                // 自定义填充模式设置为None，由我们手动处理
                PaddingMode.ISO10126 => System.Security.Cryptography.PaddingMode.None,
                PaddingMode.ANSIX923 => System.Security.Cryptography.PaddingMode.None,
                _ => System.Security.Cryptography.PaddingMode.PKCS7
            };
        }

        #endregion
    }
}
