using CryptoTool.Common.Common;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Utils;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptoTool.Common.Providers
{
    /// <summary>
    /// AES加密工具类，支持多种加密模式和密钥长度，兼容.NET Standard 2.1
    /// </summary>
    public class AESProvider : BaseCryptoProvider
    {
        #region 常量定义

        /// <summary>
        /// AES默认密钥向量 (128位)
        /// </summary>
        public static readonly byte[] AES_IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

        #endregion

        #region 属性

        /// <summary>
        /// 算法类型
        /// </summary>
        public override AlgorithmType AlgorithmType => AlgorithmType.AES;

        /// <summary>
        /// 密钥长度（字节）
        /// </summary>
        protected override int KeySize => 32; // 256位

        /// <summary>
        /// 块大小（字节）
        /// </summary>
        protected override int BlockSize => 16; // 128位

        /// <summary>
        /// IV长度（字节）
        /// </summary>
        protected override int IVSize => 16; // 128位

        #endregion

        #region 静态方法

        /// <summary>
        /// 生成AES密钥
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密钥字符串</returns>
        public override string GenerateKey(KeySize keySize = Enums.KeySize.Key256, OutputFormat outputFormat = OutputFormat.Base64)
        {
            int actualKeySize = (int)keySize / 8;
            byte[] keyBytes = CryptoCommonUtil.GenerateRandomBytes(actualKeySize);
            return CryptoCommonUtil.BytesToString(keyBytes, outputFormat);
        }

        /// <summary>
        /// 生成AES IV
        /// </summary>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>IV字符串</returns>
        public override string GenerateIV(OutputFormat outputFormat = OutputFormat.Base64)
        {
            byte[] ivBytes = CryptoCommonUtil.GenerateRandomBytes(16);
            return CryptoCommonUtil.BytesToString(ivBytes, outputFormat);
        }

        /// <summary>
        /// 加密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        public override void EncryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, 32);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? CryptoCommonUtil.GenerateRandomBytes(16) :
                CryptoCommonUtil.ProcessIV(iv, 16);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Mode = ConvertCipherMode(mode);
                aes.Padding = ConvertPaddingMode(padding);
                if (mode != CryptoMode.ECB) aes.IV = ivBytes;

                using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (var encryptor = aes.CreateEncryptor())
                using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                {
                    inputStream.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                }
            }
        }

        /// <summary>
        /// 解密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        public override void DecryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            if (string.IsNullOrEmpty(iv))
                throw new ArgumentException("解密时必须提供IV");

            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, 32);
            byte[] ivBytes = CryptoCommonUtil.ProcessIV(iv, 16);

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.Mode = ConvertCipherMode(mode);
                aes.Padding = ConvertPaddingMode(padding);
                if (mode != CryptoMode.ECB) aes.IV = ivBytes;

                using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (var decryptor = aes.CreateDecryptor())
                using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }

        #endregion

        #region 抽象方法实现

        /// <summary>
        /// 创建加密器
        /// </summary>
        protected override ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CryptoMode mode,
            CryptoPaddingMode padding, bool isEncryption)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = ConvertCipherMode(mode);
                aes.Padding = ConvertPaddingMode(padding);

                if (mode != CryptoMode.ECB && iv != null)
                    aes.IV = iv;

                return isEncryption ? aes.CreateEncryptor() : aes.CreateDecryptor();
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