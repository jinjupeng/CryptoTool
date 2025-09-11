using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;

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
        protected abstract ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CipherMode mode, 
            PaddingMode padding, bool isEncryption);

        /// <summary>
        /// 转换加密模式
        /// </summary>
        /// <param name="mode">通用加密模式</param>
        /// <returns>具体算法的加密模式</returns>
        protected abstract System.Security.Cryptography.CipherMode ConvertCipherMode(CipherMode mode);

        /// <summary>
        /// 转换填充模式
        /// </summary>
        /// <param name="padding">通用填充模式</param>
        /// <returns>具体算法的填充模式</returns>
        protected abstract System.Security.Cryptography.PaddingMode ConvertPaddingMode(PaddingMode padding);

        #endregion

        #region ICryptoProvider 实现

        /// <summary>
        /// 加密字符串
        /// </summary>
        public virtual string Encrypt(string plaintext, string key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw CryptoCommon.CreateArgumentException(nameof(plaintext), "明文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommon.CreateArgumentException(nameof(key), "密钥不能为空");

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = CryptoCommon.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? CryptoCommon.GenerateRandomBytes(IVSize) : 
                CryptoCommon.ProcessIV(iv, IVSize);

            byte[] encryptedBytes = Encrypt(plainBytes, keyBytes, mode, padding, ivBytes);
            return CryptoCommon.BytesToString(encryptedBytes, outputFormat);
        }

        /// <summary>
        /// 解密字符串
        /// </summary>
        public virtual string Decrypt(string ciphertext, string key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, InputFormat inputFormat = InputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw CryptoCommon.CreateArgumentException(nameof(ciphertext), "密文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommon.CreateArgumentException(nameof(key), "密钥不能为空");

            byte[] cipherBytes = CryptoCommon.StringToBytes(ciphertext, inputFormat);
            byte[] keyBytes = CryptoCommon.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? 
                throw new ArgumentException("解密时必须提供IV") : CryptoCommon.ProcessIV(iv, IVSize);

            byte[] decryptedBytes = Decrypt(cipherBytes, keyBytes, mode, padding, ivBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// 加密字节数组
        /// </summary>
        public virtual byte[] Encrypt(byte[] data, byte[] key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, byte[] iv = null)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommon.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommon.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommon.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommon.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CipherMode.ECB && (iv == null || !CryptoCommon.ValidateIVLength(iv, IVSize)))
                throw CryptoCommon.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");

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
        public virtual byte[] Decrypt(byte[] data, byte[] key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, byte[] iv = null)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommon.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommon.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommon.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommon.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CipherMode.ECB && (iv == null || !CryptoCommon.ValidateIVLength(iv, IVSize)))
                throw CryptoCommon.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null)
        {
            if (!CryptoCommon.ValidateFilePath(inputFilePath, true))
                throw new FileNotFoundException($"输入文件不存在: {inputFilePath}");
            if (!CryptoCommon.ValidateFilePath(outputFilePath, false))
                throw new ArgumentException($"输出文件路径无效: {outputFilePath}");

            byte[] keyBytes = CryptoCommon.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? CryptoCommon.GenerateRandomBytes(IVSize) : 
                CryptoCommon.ProcessIV(iv, IVSize);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null)
        {
            if (!CryptoCommon.ValidateFilePath(inputFilePath, true))
                throw new FileNotFoundException($"输入文件不存在: {inputFilePath}");
            if (!CryptoCommon.ValidateFilePath(outputFilePath, false))
                throw new ArgumentException($"输出文件路径无效: {outputFilePath}");

            byte[] keyBytes = CryptoCommon.ProcessKey(key, KeySize);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? 
                throw new ArgumentException("解密时必须提供IV") : CryptoCommon.ProcessIV(iv, IVSize);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 异步解密文件
        /// </summary>
        public virtual async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key, 
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 生成密钥
        /// </summary>
        public virtual string GenerateKey(KeySize keySize = KeySize.Key256, OutputFormat format = OutputFormat.Base64)
        {
            int actualKeySize = (int)keySize / 8;
            if (actualKeySize != KeySize)
                throw new ArgumentException($"不支持的密钥长度: {keySize}，当前算法支持{KeySize * 8}位");

            byte[] keyBytes = CryptoCommon.GenerateRandomBytes(KeySize);
            return CryptoCommon.BytesToString(keyBytes, format);
        }

        /// <summary>
        /// 生成初始化向量
        /// </summary>
        public virtual string GenerateIV(OutputFormat format = OutputFormat.Base64)
        {
            byte[] ivBytes = CryptoCommon.GenerateRandomBytes(IVSize);
            return CryptoCommon.BytesToString(ivBytes, format);
        }

        /// <summary>
        /// 验证密钥有效性
        /// </summary>
        public virtual bool ValidateKey(string key, InputFormat format = InputFormat.UTF8)
        {
            try
            {
                if (!CryptoCommon.ValidateStringFormat(key, format))
                    return false;

                byte[] keyBytes = CryptoCommon.StringToBytes(key, format);
                return CryptoCommon.ValidateKeyLength(keyBytes, KeySize, AlgorithmType);
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
            CipherMode mode, PaddingMode padding, byte[] iv)
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
            CipherMode mode, PaddingMode padding, byte[] iv)
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
