using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common.Common
{
    /// <summary>
    /// 基础加密提供者抽象类
    /// </summary>
    public abstract class BaseCryptoProvider : ICryptoProvider
    {
        #region 抽象属性

        /// <summary>
        /// 算法类型
        /// </summary>
        public abstract AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 密钥长度（字节）
        /// </summary>
        protected abstract int KeySize { get; }

        /// <summary>
        /// 块大小（字节）
        /// </summary>
        protected abstract int BlockSize { get; }

        /// <summary>
        /// IV长度（字节）
        /// </summary>
        protected abstract int IVSize { get; }

        #endregion

        #region 抽象方法

        /// <summary>
        /// 创建加密器
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="isEncryption">是否为加密</param>
        /// <returns>加密器</returns>
        protected abstract ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CryptoMode mode,
            CryptoPaddingMode padding, bool isEncryption);

        /// <summary>
        /// 转换加密模式
        /// </summary>
        /// <param name="mode">通用加密模式</param>
        /// <returns>具体算法的加密模式</returns>
        protected abstract System.Security.Cryptography.CipherMode ConvertCipherMode(CryptoMode mode);

        /// <summary>
        /// 转换填充模式
        /// </summary>
        /// <param name="padding">通用填充模式</param>
        /// <returns>具体算法的填充模式</returns>
        protected abstract System.Security.Cryptography.PaddingMode ConvertPaddingMode(CryptoPaddingMode padding);

        #endregion

        #region ICryptoProvider 实现

        /// <summary>
        /// 加密字符串
        /// </summary>
        public virtual string Encrypt(string plaintext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw CryptoCommonUtil.CreateArgumentException(nameof(plaintext), "明文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? CryptoCommonUtil.GenerateRandomBytes(IVSize) :
                CryptoCommonUtil.ProcessIV(iv, IVSize);

            byte[] encryptedBytes = Encrypt(plainBytes, keyBytes, mode, padding, ivBytes);
            return CryptoCommonUtil.BytesToString(encryptedBytes, outputFormat);
        }

        /// <summary>
        /// 解密字符串
        /// </summary>
        public virtual string Decrypt(string ciphertext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, InputFormat inputFormat = InputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw CryptoCommonUtil.CreateArgumentException(nameof(ciphertext), "密文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            byte[] cipherBytes = CryptoCommonUtil.StringToBytes(ciphertext, inputFormat);
            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ?
                throw new ArgumentException("解密时必须提供IV") : CryptoCommonUtil.ProcessIV(iv, IVSize);

            byte[] decryptedBytes = Decrypt(cipherBytes, keyBytes, mode, padding, ivBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// 加密字节数组
        /// </summary>
        public virtual byte[] Encrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommonUtil.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommonUtil.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CryptoMode.ECB && (iv == null || !CryptoCommonUtil.ValidateIVLength(iv, IVSize)))
                throw CryptoCommonUtil.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");

            using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, true))
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }
                return memoryStream.ToArray();
            }
        }

        /// <summary>
        /// 解密字节数组
        /// </summary>
        public virtual byte[] Decrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommonUtil.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommonUtil.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CryptoMode.ECB && (iv == null || !CryptoCommonUtil.ValidateIVLength(iv, IVSize)))
                throw CryptoCommonUtil.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");

            using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, false))
            using (var memoryStream = new MemoryStream(data))
            using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
            using (var resultStream = new MemoryStream())
            {
                cryptoStream.CopyTo(resultStream);
                return resultStream.ToArray();
            }
        }

        /// <summary>
        /// 加密文件
        /// </summary>
        public virtual void EncryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            if (!CryptoCommonUtil.ValidateFilePath(inputFilePath, true))
                throw new FileNotFoundException($"输入文件不存在: {inputFilePath}");
            if (!CryptoCommonUtil.ValidateFilePath(outputFilePath, false))
                throw new ArgumentException($"输出文件路径无效: {outputFilePath}");

            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? CryptoCommonUtil.GenerateRandomBytes(IVSize) :
                CryptoCommonUtil.ProcessIV(iv, IVSize);

            using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                EncryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
            }
        }

        /// <summary>
        /// 解密文件
        /// </summary>
        public virtual void DecryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            if (!CryptoCommonUtil.ValidateFilePath(inputFilePath, true))
                throw new FileNotFoundException($"输入文件不存在: {inputFilePath}");
            if (!CryptoCommonUtil.ValidateFilePath(outputFilePath, false))
                throw new ArgumentException($"输出文件路径无效: {outputFilePath}");

            byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ?
                throw new ArgumentException("解密时必须提供IV") : CryptoCommonUtil.ProcessIV(iv, IVSize);

            using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                DecryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
            }
        }

        /// <summary>
        /// 异步加密文件
        /// </summary>
        public virtual async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 异步解密文件
        /// </summary>
        public virtual async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 生成密钥
        /// </summary>
        public virtual string GenerateKey(Enums.KeySize keySize = Enums.KeySize.Key256, OutputFormat format = OutputFormat.Base64)
        {
            int actualKeySize = (int)keySize / 8;
            if (actualKeySize != this.KeySize)
                throw new ArgumentException($"不支持的密钥长度: {keySize}，当前算法支持{this.KeySize * 8}位");

            byte[] keyBytes = CryptoCommonUtil.GenerateRandomBytes(this.KeySize);
            return CryptoCommonUtil.BytesToString(keyBytes, format);
        }

        /// <summary>
        /// 生成初始化向量
        /// </summary>
        public virtual string GenerateIV(OutputFormat format = OutputFormat.Base64)
        {
            byte[] ivBytes = CryptoCommonUtil.GenerateRandomBytes(IVSize);
            return CryptoCommonUtil.BytesToString(ivBytes, format);
        }

        /// <summary>
        /// 验证密钥有效性
        /// </summary>
        public virtual bool ValidateKey(string key, InputFormat format = InputFormat.UTF8)
        {
            try
            {
                if (!CryptoCommonUtil.ValidateStringFormat(key, format))
                    return false;

                byte[] keyBytes = CryptoCommonUtil.StringToBytes(key, format);
                return CryptoCommonUtil.ValidateKeyLength(keyBytes, KeySize, AlgorithmType);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 受保护的辅助方法

        /// <summary>
        /// 加密流
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        protected virtual void EncryptStream(Stream inputStream, Stream outputStream, byte[] key,
            CryptoMode mode, CryptoPaddingMode padding, byte[] iv)
        {
            using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, true))
            using (var cryptoStream = new CryptoStream(outputStream, cryptoTransform, CryptoStreamMode.Write))
            {
                inputStream.CopyTo(cryptoStream);
                cryptoStream.FlushFinalBlock();
            }
        }

        /// <summary>
        /// 解密流
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        protected virtual void DecryptStream(Stream inputStream, Stream outputStream, byte[] key,
            CryptoMode mode, CryptoPaddingMode padding, byte[] iv)
        {
            using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, false))
            using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read))
            {
                cryptoStream.CopyTo(outputStream);
            }
        }

        #endregion
    }
}
