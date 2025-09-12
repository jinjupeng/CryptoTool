using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoTool.Common.Common
{
    /// <summary>
    /// 基础加密提供者抽象类
    /// 提供了对称加密算法的通用实现，包括字符串、字节数组、文件和流的加密解密操作
    /// 支持多种加密模式、填充方式，不涉及具体的格式转换逻辑
    /// </summary>
    public abstract class BaseCryptoProvider : ICryptoProvider
    {
        #region 常量定义

        /// <summary>
        /// 默认文件缓冲区大小（64KB）
        /// </summary>
        protected const int DEFAULT_BUFFER_SIZE = 65536;

        /// <summary>
        /// 最小缓冲区大小（4KB）
        /// </summary>
        protected const int MIN_BUFFER_SIZE = 4096;

        /// <summary>
        /// 最大缓冲区大小（1MB）
        /// </summary>
        protected const int MAX_BUFFER_SIZE = 1048576;

        #endregion

        #region 抽象属性

        /// <summary>
        /// 获取算法类型
        /// </summary>
        /// <value>算法类型枚举值</value>
        public abstract AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 获取密钥长度（字节）
        /// 由具体的加密算法实现类定义
        /// </summary>
        /// <value>密钥长度（字节数）</value>
        protected abstract int KeySize { get; }

        /// <summary>
        /// 获取块大小（字节）
        /// 用于确定加密算法的块长度
        /// </summary>
        /// <value>块大小（字节数）</value>
        protected abstract int BlockSize { get; }

        /// <summary>
        /// 获取初始化向量长度（字节）
        /// 通常与块大小相同
        /// </summary>
        /// <value>IV长度（字节数）</value>
        protected abstract int IVSize { get; }

        #endregion

        #region 抽象方法

        /// <summary>
        /// 创建加密转换器
        /// 由具体的加密算法实现类重写，创建对应的加密器实例
        /// </summary>
        /// <param name="key">加密密钥（字节数组）</param>
        /// <param name="iv">初始化向量（字节数组），ECB模式下可为null</param>
        /// <param name="mode">加密模式（ECB、CBC、CFB、OFB等）</param>
        /// <param name="padding">填充模式（PKCS7、PKCS5、Zeros等）</param>
        /// <param name="isEncryption">是否为加密操作，true为加密，false为解密</param>
        /// <returns>加密转换器实例</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="NotSupportedException">不支持的模式或填充时抛出</exception>
        protected abstract ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CryptoMode mode,
            CryptoPaddingMode padding, bool isEncryption);

        /// <summary>
        /// 转换通用加密模式为具体算法的加密模式
        /// 用于将统一的枚举转换为.NET Framework的CipherMode
        /// </summary>
        /// <param name="mode">通用加密模式</param>
        /// <returns>具体算法的加密模式</returns>
        /// <exception cref="NotSupportedException">不支持的加密模式时抛出</exception>
        protected abstract System.Security.Cryptography.CipherMode ConvertCipherMode(CryptoMode mode);

        /// <summary>
        /// 转换通用填充模式为具体算法的填充模式
        /// 用于将统一的枚举转换为.NET Framework的PaddingMode
        /// </summary>
        /// <param name="padding">通用填充模式</param>
        /// <returns>具体算法的填充模式</returns>
        /// <exception cref="NotSupportedException">不支持的填充模式时抛出</exception>
        protected abstract System.Security.Cryptography.PaddingMode ConvertPaddingMode(CryptoPaddingMode padding);

        #endregion

        #region ICryptoProvider 接口实现

        /// <summary>
        /// 加密字符串
        /// 将UTF-8编码的明文字符串加密，返回Base64编码的密文字符串
        /// </summary>
        /// <param name="plaintext">待加密的明文字符串</param>
        /// <param name="key">加密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），为空时自动生成</param>
        /// <returns>加密后的密文字符串（Base64编码）</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">加密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// string encrypted = provider.Encrypt("Hello World", "myKey123", CryptoMode.CBC, CryptoPaddingMode.PKCS7);
        /// </code>
        /// </example>
        public virtual string Encrypt(string plaintext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            // 参数验证
            ValidateEncryptStringParameters(plaintext, key);

            try
            {
                // 字符串转字节数组
                byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
                byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
                byte[] ivBytes = ProcessIVForMode(iv, mode);

                // 执行加密
                byte[] encryptedBytes = Encrypt(plainBytes, keyBytes, mode, padding, ivBytes);
                
                // 转换为Base64输出
                return Convert.ToBase64String(encryptedBytes);
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"字符串加密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 解密字符串
        /// 将Base64编码的密文字符串解密为UTF-8编码的明文字符串
        /// </summary>
        /// <param name="ciphertext">待解密的密文字符串（Base64编码）</param>
        /// <param name="key">解密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），ECB模式下可为空</param>
        /// <returns>解密后的明文字符串</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">解密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// string decrypted = provider.Decrypt(encrypted, "myKey123", CryptoMode.CBC, CryptoPaddingMode.PKCS7, "myIV");
        /// </code>
        /// </example>
        public virtual string Decrypt(string ciphertext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            // 参数验证
            ValidateDecryptStringParameters(ciphertext, key, iv, mode);

            try
            {
                // 字符串转字节数组
                byte[] cipherBytes = Convert.FromBase64String(ciphertext);
                byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
                byte[] ivBytes = CryptoCommonUtil.ProcessIV(iv, IVSize);

                // 执行解密
                byte[] decryptedBytes = Decrypt(cipherBytes, keyBytes, mode, padding, ivBytes);
                
                // 转换为UTF-8字符串
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"字符串解密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 加密字节数组
        /// 对原始字节数组执行加密操作，支持各种加密模式和填充方式
        /// </summary>
        /// <param name="data">待加密的字节数组</param>
        /// <param name="key">加密密钥（字节数组）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字节数组），ECB模式下可为null</param>
        /// <returns>加密后的字节数组</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">加密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// byte[] encrypted = provider.Encrypt(dataBytes, keyBytes, CryptoMode.CBC, CryptoPaddingMode.PKCS7, ivBytes);
        /// </code>
        /// </example>
        public virtual byte[] Encrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            // 参数验证
            ValidateEncryptBytesParameters(data, key, iv, mode);

            try
            {
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
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"字节数组加密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 解密字节数组
        /// 对加密的字节数组执行解密操作，还原为原始数据
        /// </summary>
        /// <param name="data">待解密的字节数组</param>
        /// <param name="key">解密密钥（字节数组）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字节数组），ECB模式下可为null</param>
        /// <returns>解密后的字节数组</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">解密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// byte[] decrypted = provider.Decrypt(encryptedBytes, keyBytes, CryptoMode.CBC, CryptoPaddingMode.PKCS7, ivBytes);
        /// </code>
        /// </example>
        public virtual byte[] Decrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            // 参数验证
            ValidateDecryptBytesParameters(data, key, iv, mode);

            try
            {
                using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, false))
                using (var memoryStream = new MemoryStream(data))
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                using (var resultStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(resultStream);
                    return resultStream.ToArray();
                }
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"字节数组解密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 加密文件
        /// 读取指定文件并加密，将结果保存到输出文件
        /// 支持大文件的流式处理，内存占用低
        /// </summary>
        /// <param name="inputFilePath">输入文件的完整路径</param>
        /// <param name="outputFilePath">输出文件的完整路径</param>
        /// <param name="key">加密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），为空时自动生成</param>
        /// <exception cref="FileNotFoundException">输入文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">加密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// provider.EncryptFile(@"C:\data.txt", @"C:\data.encrypted", "myKey123", CryptoMode.CBC);
        /// </code>
        /// </example>
        public virtual void EncryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            // 参数验证
            ValidateFileParameters(inputFilePath, outputFilePath, key);

            try
            {
                // 处理密钥和IV
                byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
                byte[] ivBytes = ProcessIVForMode(iv, mode);

                // 执行文件加密
                using (var inputStream = CreateFileInputStream(inputFilePath))
                using (var outputStream = CreateFileOutputStream(outputFilePath))
                {
                    EncryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
                }
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is FileNotFoundException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"文件加密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 解密文件
        /// 读取加密文件并解密，将结果保存到输出文件
        /// 支持大文件的流式处理，内存占用低
        /// </summary>
        /// <param name="inputFilePath">输入文件的完整路径</param>
        /// <param name="outputFilePath">输出文件的完整路径</param>
        /// <param name="key">解密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），ECB模式下可为空</param>
        /// <exception cref="FileNotFoundException">输入文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">解密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// provider.DecryptFile(@"C:\data.encrypted", @"C:\data.txt", "myKey123", CryptoMode.CBC, CryptoPaddingMode.PKCS7, "myIV");
        /// </code>
        /// </example>
        public virtual void DecryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            // 参数验证
            ValidateFileDecryptParameters(inputFilePath, outputFilePath, key, iv, mode);

            try
            {
                // 处理密钥和IV
                byte[] keyBytes = CryptoCommonUtil.ProcessKey(key, KeySize);
                byte[] ivBytes = CryptoCommonUtil.ProcessIV(iv, IVSize);

                // 执行文件解密
                using (var inputStream = CreateFileInputStream(inputFilePath))
                using (var outputStream = CreateFileOutputStream(outputFilePath))
                {
                    DecryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
                }
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is FileNotFoundException))
            {
                throw CryptoCommonUtil.CreateCryptoException($"文件解密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 异步加密文件
        /// 在后台线程中执行文件加密操作，不阻塞调用线程
        /// 适用于大文件或需要响应性的应用程序
        /// </summary>
        /// <param name="inputFilePath">输入文件的完整路径</param>
        /// <param name="outputFilePath">输出文件的完整路径</param>
        /// <param name="key">加密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），为空时自动生成</param>
        /// <returns>表示异步操作的任务</returns>
        /// <exception cref="FileNotFoundException">输入文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">加密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// await provider.EncryptFileAsync(@"C:\data.txt", @"C:\data.encrypted", "myKey123");
        /// </code>
        /// </example>
        public virtual async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, key, mode, padding, iv))
                      .ConfigureAwait(false);
        }

        /// <summary>
        /// 异步解密文件
        /// 在后台线程中执行文件解密操作，不阻塞调用线程
        /// 适用于大文件或需要响应性的应用程序
        /// </summary>
        /// <param name="inputFilePath">输入文件的完整路径</param>
        /// <param name="outputFilePath">输出文件的完整路径</param>
        /// <param name="key">解密密钥（字符串格式）</param>
        /// <param name="mode">加密模式，默认为CBC</param>
        /// <param name="padding">填充模式，默认为PKCS7</param>
        /// <param name="iv">初始化向量（字符串格式），ECB模式下可为空</param>
        /// <returns>表示异步操作的任务</returns>
        /// <exception cref="FileNotFoundException">输入文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        /// <exception cref="CryptographicException">解密操作失败时抛出</exception>
        /// <example>
        /// <code>
        /// await provider.DecryptFileAsync(@"C:\data.encrypted", @"C:\data.txt", "myKey123", CryptoMode.CBC, CryptoPaddingMode.PKCS7, "myIV");
        /// </code>
        /// </example>
        public virtual async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, key, mode, padding, iv))
                      .ConfigureAwait(false);
        }

        /// <summary>
        /// 生成适用于当前算法的随机密钥
        /// 根据指定的密钥长度生成加密强度的随机密钥
        /// </summary>
        /// <param name="keySize">密钥长度枚举值，默认为256位</param>
        /// <returns>生成的密钥字符串（Base64格式）</returns>
        /// <exception cref="ArgumentException">密钥长度不受支持时抛出</exception>
        /// <example>
        /// <code>
        /// string key = provider.GenerateKey(KeySize.Key256);
        /// </code>
        /// </example>
        public virtual string GenerateKey(Enums.KeySize keySize = Enums.KeySize.Key256)
        {
            int actualKeySize = (int)keySize / 8;
            if (actualKeySize != this.KeySize)
                throw new ArgumentException($"不支持的密钥长度: {keySize}（{actualKeySize}字节），当前算法支持{this.KeySize}字节（{this.KeySize * 8}位）");

            byte[] keyBytes = CryptoCommonUtil.GenerateRandomBytes(this.KeySize);
            return Convert.ToBase64String(keyBytes);
        }

        /// <summary>
        /// 生成适用于当前算法的随机初始化向量
        /// 为非ECB模式的加密操作生成安全的随机初始化向量
        /// </summary>
        /// <returns>生成的初始化向量字符串（Base64格式）</returns>
        /// <example>
        /// <code>
        /// string iv = provider.GenerateIV();
        /// </code>
        /// </example>
        public virtual string GenerateIV()
        {
            byte[] ivBytes = CryptoCommonUtil.GenerateRandomBytes(IVSize);
            return Convert.ToBase64String(ivBytes);
        }

        /// <summary>
        /// 验证密钥的有效性
        /// 检查密钥格式和长度是否符合当前算法的要求
        /// </summary>
        /// <param name="key">待验证的密钥字符串</param>
        /// <returns>true表示密钥有效，false表示无效</returns>
        /// <example>
        /// <code>
        /// bool isValid = provider.ValidateKey("myKey123");
        /// </code>
        /// </example>
        public virtual bool ValidateKey(string key)
        {
            try
            {
                if (string.IsNullOrEmpty(key))
                    return false;

                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
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
        /// 加密流数据
        /// 从输入流读取数据，加密后写入输出流
        /// 支持大数据量的流式处理，内存占用低
        /// </summary>
        /// <param name="inputStream">输入数据流</param>
        /// <param name="outputStream">输出数据流</param>
        /// <param name="key">加密密钥（字节数组）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量（字节数组）</param>
        /// <exception cref="CryptographicException">加密操作失败时抛出</exception>
        protected virtual void EncryptStream(Stream inputStream, Stream outputStream, byte[] key,
            CryptoMode mode, CryptoPaddingMode padding, byte[] iv)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream), "输入流不能为空");
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream), "输出流不能为空");

            try
            {
                using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, true))
                using (var cryptoStream = new CryptoStream(outputStream, cryptoTransform, CryptoStreamMode.Write, true))
                {
                    inputStream.CopyTo(cryptoStream, DEFAULT_BUFFER_SIZE);
                    cryptoStream.FlushFinalBlock();
                }
            }
            catch (Exception ex)
            {
                throw CryptoCommonUtil.CreateCryptoException($"流加密失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 解密流数据
        /// 从输入流读取加密数据，解密后写入输出流
        /// 支持大数据量的流式处理，内存占用低
        /// </summary>
        /// <param name="inputStream">输入数据流（包含加密数据）</param>
        /// <param name="outputStream">输出数据流（解密后的数据）</param>
        /// <param name="key">解密密钥（字节数组）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量（字节数组）</param>
        /// <exception cref="CryptographicException">解密操作失败时抛出</exception>
        protected virtual void DecryptStream(Stream inputStream, Stream outputStream, byte[] key,
            CryptoMode mode, CryptoPaddingMode padding, byte[] iv)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream), "输入流不能为空");
            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream), "输出流不能为空");

            try
            {
                using (var cryptoTransform = CreateCryptoTransform(key, iv, mode, padding, false))
                using (var cryptoStream = new CryptoStream(inputStream, cryptoTransform, CryptoStreamMode.Read, true))
                {
                    cryptoStream.CopyTo(outputStream, DEFAULT_BUFFER_SIZE);
                }
            }
            catch (Exception ex)
            {
                throw CryptoCommonUtil.CreateCryptoException($"流解密失败: {ex.Message}", ex);
            }
        }

        #endregion

        #region 私有辅助方法

        /// <summary>
        /// 验证字符串加密操作的参数
        /// </summary>
        /// <param name="plaintext">明文字符串</param>
        /// <param name="key">密钥字符串</param>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private static void ValidateEncryptStringParameters(string plaintext, string key)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw CryptoCommonUtil.CreateArgumentException(nameof(plaintext), "明文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");
        }

        /// <summary>
        /// 验证字符串解密操作的参数
        /// </summary>
        /// <param name="ciphertext">密文字符串</param>
        /// <param name="key">密钥字符串</param>
        /// <param name="iv">初始化向量</param>
        /// <param name="mode">加密模式</param>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private static void ValidateDecryptStringParameters(string ciphertext, string key, string iv, CryptoMode mode)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw CryptoCommonUtil.CreateArgumentException(nameof(ciphertext), "密文不能为空");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");
            if (mode != CryptoMode.ECB && string.IsNullOrEmpty(iv))
                throw new ArgumentException($"{mode}模式解密时必须提供初始化向量", nameof(iv));
        }

        /// <summary>
        /// 验证字节数组加密操作的参数
        /// </summary>
        /// <param name="data">数据字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始化向量字节数组</param>
        /// <param name="mode">加密模式</param>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private void ValidateEncryptBytesParameters(byte[] data, byte[] key, byte[] iv, CryptoMode mode)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommonUtil.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommonUtil.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CryptoMode.ECB && (iv == null || !CryptoCommonUtil.ValidateIVLength(iv, IVSize)))
                throw CryptoCommonUtil.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");
        }

        /// <summary>
        /// 验证字节数组解密操作的参数
        /// </summary>
        /// <param name="data">数据字节数组</param>
        /// <param name="key">密钥字节数组</param>
        /// <param name="iv">初始化向量字节数组</param>
        /// <param name="mode">加密模式</param>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private void ValidateDecryptBytesParameters(byte[] data, byte[] key, byte[] iv, CryptoMode mode)
        {
            if (data == null || data.Length == 0)
                throw CryptoCommonUtil.CreateArgumentException(nameof(data), "数据不能为空");
            if (key == null)
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");

            if (!CryptoCommonUtil.ValidateKeyLength(key, KeySize, AlgorithmType))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), $"密钥长度必须为{KeySize}字节");

            if (mode != CryptoMode.ECB && (iv == null || !CryptoCommonUtil.ValidateIVLength(iv, IVSize)))
                throw CryptoCommonUtil.CreateArgumentException(nameof(iv), $"IV长度必须为{IVSize}字节");
        }

        /// <summary>
        /// 验证文件操作的基本参数
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <exception cref="FileNotFoundException">输入文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private static void ValidateFileParameters(string inputFilePath, string outputFilePath, string key)
        {
            if (!CryptoCommonUtil.ValidateFilePath(inputFilePath, true))
                throw new FileNotFoundException($"输入文件不存在: {inputFilePath}");
            if (!CryptoCommonUtil.ValidateFilePath(outputFilePath, false))
                throw new ArgumentException($"输出文件路径无效: {outputFilePath}");
            if (string.IsNullOrEmpty(key))
                throw CryptoCommonUtil.CreateArgumentException(nameof(key), "密钥不能为空");
        }

        /// <summary>
        /// 验证文件解密操作的参数
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <param name="mode">加密模式</param>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        private static void ValidateFileDecryptParameters(string inputFilePath, string outputFilePath, string key, string iv, CryptoMode mode)
        {
            ValidateFileParameters(inputFilePath, outputFilePath, key);
            
            if (mode != CryptoMode.ECB && string.IsNullOrEmpty(iv))
                throw new ArgumentException($"{mode}模式解密时必须提供初始化向量", nameof(iv));
        }

        /// <summary>
        /// 根据加密模式处理初始化向量
        /// ECB模式不需要IV，其他模式需要生成或验证IV
        /// </summary>
        /// <param name="iv">初始化向量字符串</param>
        /// <param name="mode">加密模式</param>
        /// <returns>处理后的IV字节数组</returns>
        private byte[] ProcessIVForMode(string iv, CryptoMode mode)
        {
            if (mode == CryptoMode.ECB)
            {
                return null; // ECB模式不需要IV
            }

            return string.IsNullOrEmpty(iv) 
                ? CryptoCommonUtil.GenerateRandomBytes(IVSize) 
                : CryptoCommonUtil.ProcessIV(iv, IVSize);
        }

        /// <summary>
        /// 创建文件输入流
        /// 使用优化的缓冲区大小以提高性能
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>文件输入流</returns>
        private static FileStream CreateFileInputStream(string filePath)
        {
            return new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, DEFAULT_BUFFER_SIZE);
        }

        /// <summary>
        /// 创建文件输出流
        /// 使用优化的缓冲区大小以提高性能
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>文件输出流</returns>
        private static FileStream CreateFileOutputStream(string filePath)
        {
            return new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, DEFAULT_BUFFER_SIZE);
        }

        #endregion
    }
}
