using CryptoTool.Common.Common;
using CryptoTool.Common.Enums;
using System.Security.Cryptography;

namespace CryptoTool.Common.Providers
{
    /// <summary>
    /// DES对称加密工具类
    /// 提供字符串、文件、流的DES加密解密功能
    /// 支持多种加密模式、填充方式和输出格式
    /// </summary>
    public class DESProvider : BaseCryptoProvider
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
        protected override ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CryptoMode mode,
            CryptoPaddingMode padding, bool isEncryption)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = key;
                des.Mode = ConvertCipherMode(mode);
                des.Padding = ConvertPaddingMode(padding);

                if (mode != CryptoMode.ECB && iv != null)
                    des.IV = iv;

                return isEncryption ? des.CreateEncryptor() : des.CreateDecryptor();
            }
        }

        /// <summary>
        /// 转换加密模式
        /// </summary>
        protected override CipherMode ConvertCipherMode(CryptoMode mode)
        {
            return mode switch
            {
                CryptoMode.ECB => CipherMode.ECB,
                CryptoMode.CBC => CipherMode.CBC,
                CryptoMode.CFB => CipherMode.CFB,
                CryptoMode.OFB => CipherMode.OFB,
                _ => CipherMode.CBC
            };
        }

        /// <summary>
        /// 转换填充模式
        /// </summary>
        protected override PaddingMode ConvertPaddingMode(CryptoPaddingMode padding)
        {
            return padding switch
            {
                CryptoPaddingMode.PKCS7 => PaddingMode.PKCS7,
                CryptoPaddingMode.PKCS5 => PaddingMode.PKCS7, // .NET中PKCS5等同于PKCS7
                CryptoPaddingMode.Zeros => PaddingMode.Zeros,
                CryptoPaddingMode.None => PaddingMode.None,
                // 自定义填充模式设置为None，由我们手动处理
                CryptoPaddingMode.ISO10126 => PaddingMode.None,
                CryptoPaddingMode.ANSIX923 => PaddingMode.None,
                _ => PaddingMode.PKCS7
            };
        }

        #endregion
    }
}
