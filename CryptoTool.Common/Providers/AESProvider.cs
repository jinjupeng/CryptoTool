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

        #region 静态兼容方法 - 保持向后兼容

        /// <summary>
        /// AES加密（CBC模式，PKCS7填充）
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptByAES(string plainText, string key)
        {
            var provider = new AESProvider();
            return provider.Encrypt(plainText, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7);
        }

        /// <summary>
        /// AES解密（CBC模式，PKCS7填充）
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥</param>
        /// <returns>明文</returns>
        public static string DecryptByAES(string cipherText, string key)
        {
            var provider = new AESProvider();
            return provider.Decrypt(cipherText, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7);
        }

        /// <summary>
        /// AES加密（指定模式和填充）
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptByAES(string plainText, string key, string mode, string padding, string iv = null)
        {
            var provider = new AESProvider();
            var cryptoMode = ParseMode(mode);
            var paddingMode = ParsePadding(padding);
            return provider.Encrypt(plainText, key, cryptoMode, paddingMode, iv);
        }

        /// <summary>
        /// AES解密（指定模式和填充）
        /// </summary>
        /// <param name="cipherText">Base64编码的密文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>明文</returns>
        public static string DecryptByAES(string cipherText, string key, string mode, string padding, string iv = null)
        {
            var provider = new AESProvider();
            var cryptoMode = ParseMode(mode);
            var paddingMode = ParsePadding(padding);
            return provider.Decrypt(cipherText, key, cryptoMode, paddingMode, iv);
        }

        /// <summary>
        /// 生成AES密钥
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>Base64编码的密钥</returns>
        public static string GenerateAESKey(int keySize = 256)
        {
            var provider = new AESProvider();
            var keySizeEnum = keySize switch
            {
                128 => Enums.KeySize.Key128,
                192 => Enums.KeySize.Key192,
                256 => Enums.KeySize.Key256,
                _ => Enums.KeySize.Key256
            };
            return provider.GenerateKey(keySizeEnum);
        }

        /// <summary>
        /// 生成AES初始化向量
        /// </summary>
        /// <returns>Base64编码的IV</returns>
        public static string GenerateAESIV()
        {
            var provider = new AESProvider();
            return provider.GenerateIV();
        }

        #endregion

        #region 私有辅助方法

        /// <summary>
        /// 解析加密模式
        /// </summary>
        private static CryptoMode ParseMode(string mode)
        {
            return mode?.ToUpperInvariant() switch
            {
                "ECB" => CryptoMode.ECB,
                "CBC" => CryptoMode.CBC,
                "CFB" => CryptoMode.CFB,
                "OFB" => CryptoMode.OFB,
                _ => CryptoMode.CBC
            };
        }

        /// <summary>
        /// 解析填充模式
        /// </summary>
        private static CryptoPaddingMode ParsePadding(string padding)
        {
            return padding?.ToUpperInvariant() switch
            {
                "PKCS7" => CryptoPaddingMode.PKCS7,
                "PKCS5" => CryptoPaddingMode.PKCS5,
                "ZEROS" => CryptoPaddingMode.Zeros,
                "NONE" => CryptoPaddingMode.None,
                "ISO10126" => CryptoPaddingMode.ISO10126,
                "ANSIX923" => CryptoPaddingMode.ANSIX923,
                _ => CryptoPaddingMode.PKCS7
            };
        }

        #endregion
    }
}