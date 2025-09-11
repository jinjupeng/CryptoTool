using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common
{
    /// <summary>
    /// AES加密工具类，支持多种加密模式和密钥长度，兼容.NET Standard 2.1
    /// </summary>
    public class AESUtil
    {
        #region 常量定义

        /// <summary>
        /// AES默认密钥向量 (128位)
        /// </summary>
        public static readonly byte[] AES_IV = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };

        #endregion

        #region 枚举定义

        /// <summary>
        /// AES加密模式
        /// </summary>
        public enum AESMode
        {
            /// <summary>
            /// 电子密码本模式
            /// </summary>
            ECB,
            /// <summary>
            /// 密码块链接模式
            /// </summary>
            CBC,
            /// <summary>
            /// 密码反馈模式
            /// </summary>
            CFB,
            /// <summary>
            /// 输出反馈模式
            /// </summary>
            OFB
        }

        /// <summary>
        /// AES填充模式
        /// </summary>
        public enum AESPadding
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

        /// <summary>
        /// AES密钥长度
        /// </summary>
        public enum AESKeySize
        {
            /// <summary>
            /// 128位密钥
            /// </summary>
            AES128 = 128,
            /// <summary>
            /// 192位密钥
            /// </summary>
            AES192 = 192,
            /// <summary>
            /// 256位密钥
            /// </summary>
            AES256 = 256
        }

        /// <summary>
        /// 输出格式
        /// </summary>
        public enum OutputFormat
        {
            /// <summary>
            /// Base64格式
            /// </summary>
            Base64,
            /// <summary>
            /// 十六进制格式
            /// </summary>
            Hex
        }

        #endregion

        #region 基础AES加密解密方法

        /// <summary>
        /// AES加密（使用默认参数）
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptByAES(string plaintext, string key)
        {
            return EncryptByAES(plaintext, key, AESMode.CBC, AESPadding.PKCS7, OutputFormat.Base64);
        }

        /// <summary>
        /// AES解密（使用默认参数）
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="key">密钥</param>
        /// <returns>明文</returns>
        public static string DecryptByAES(string ciphertext, string key)
        {
            return DecryptByAES(ciphertext, key, AESMode.CBC, AESPadding.PKCS7, OutputFormat.Base64);
        }

        /// <summary>
        /// AES加密（完整参数版本）
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="iv">初始向量（可选，如果不提供则使用默认IV）</param>
        /// <returns>加密后的字符串</returns>
        public static string EncryptByAES(string plaintext, string key, AESMode mode = AESMode.CBC,
            AESPadding padding = AESPadding.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空", nameof(plaintext));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            byte[] encryptedBytes = EncryptByAES(plainBytes, keyBytes, ivBytes, mode, padding);

            return outputFormat == OutputFormat.Base64
                ? Convert.ToBase64String(encryptedBytes)
                : BitConverter.ToString(encryptedBytes).Replace("-", "");
        }

        /// <summary>
        /// AES解密（完整参数版本）
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="outputFormat">输入格式</param>
        /// <param name="iv">初始向量（可选，如果不提供则使用默认IV）</param>
        /// <returns>解密后的明文</returns>
        public static string DecryptByAES(string ciphertext, string key, AESMode mode = AESMode.CBC,
            AESPadding padding = AESPadding.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("密文不能为空", nameof(ciphertext));
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            byte[] cipherBytes = outputFormat == OutputFormat.Base64
                ? Convert.FromBase64String(ciphertext)
                : HexStringToByteArray(ciphertext);

            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            byte[] decryptedBytes = DecryptByAES(cipherBytes, keyBytes, ivBytes, mode, padding);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        #endregion

        #region 字节数组加密解密

        /// <summary>
        /// AES加密（字节数组）
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>加密后的字节数组</returns>
        public static byte[] EncryptByAES(byte[] data, byte[] key, byte[] iv,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));
            if (key == null)
                throw new ArgumentException("密钥不能为空", nameof(key));
            if (iv == null && mode != AESMode.ECB)
                throw new ArgumentException("非ECB模式必须提供初始向量", nameof(iv));

            using (var aes = CreateAesProvider(key, iv, mode, padding))
            {
                using (var encryptor = aes.CreateEncryptor())
                {
                    return ProcessCrypto(data, encryptor, padding);
                }
            }
        }

        /// <summary>
        /// AES解密（字节数组）
        /// </summary>
        /// <param name="encryptedData">加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始向量</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>解密后的字节数组</returns>
        public static byte[] DecryptByAES(byte[] encryptedData, byte[] key, byte[] iv,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("加密数据不能为空", nameof(encryptedData));
            if (key == null)
                throw new ArgumentException("密钥不能为空", nameof(key));
            if (iv == null && mode != AESMode.ECB)
                throw new ArgumentException("非ECB模式必须提供初始向量", nameof(iv));

            using (var aes = CreateAesProvider(key, iv, mode, padding))
            {
                using (var decryptor = aes.CreateDecryptor())
                {
                    return ProcessCrypto(encryptedData, decryptor, padding, false);
                }
            }
        }

        #endregion

        #region 高级功能

        /// <summary>
        /// 生成随机AES密钥
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>Base64编码的密钥</returns>
        public static string GenerateKey(AESKeySize keySize = AESKeySize.AES256)
        {
            byte[] key = new byte[(int)keySize / 8];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// 生成随机初始向量
        /// </summary>
        /// <returns>Base64编码的IV</returns>
        public static string GenerateIV()
        {
            byte[] iv = new byte[16]; // AES块大小固定为128位
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }
            return Convert.ToBase64String(iv);
        }

        /// <summary>
        /// 文件加密
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始向量</param>
        public static void EncryptFile(string inputFilePath, string outputFilePath, string key,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7, string iv = null)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException("输入文件不存在", inputFilePath);

            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            using (var aes = CreateAesProvider(keyBytes, ivBytes, mode, padding))
            {
                using (var encryptor = aes.CreateEncryptor())
                {
                    using (var inputStream = File.OpenRead(inputFilePath))
                    {
                        using (var outputStream = File.Create(outputFilePath))
                        {
                            using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                            {
                                inputStream.CopyTo(cryptoStream);
                                cryptoStream.FlushFinalBlock();
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// 文件解密
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始向量</param>
        public static void DecryptFile(string inputFilePath, string outputFilePath, string key,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7, string iv = null)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException("输入文件不存在", inputFilePath);

            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            using (var aes = CreateAesProvider(keyBytes, ivBytes, mode, padding))
            {
                using (var decryptor = aes.CreateDecryptor())
                {
                    using (var inputStream = File.OpenRead(inputFilePath))
                    {
                        using (var outputStream = File.Create(outputFilePath))
                        {
                            using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read))
                            {
                                cryptoStream.CopyTo(outputStream);
                            }
                        }
                    }
                }
            }
        }

        #endregion

        #region 流式加密解密

        /// <summary>
        /// 流式加密
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始向量</param>
        public static void EncryptStream(Stream inputStream, Stream outputStream, string key,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7, string iv = null)
        {
            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            using (var aes = CreateAesProvider(keyBytes, ivBytes, mode, padding))
            {
                using (var encryptor = aes.CreateEncryptor())
                {
                    using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write, true))
                    {
                        inputStream.CopyTo(cryptoStream);
                        cryptoStream.FlushFinalBlock();
                    }
                }
            }
        }

        /// <summary>
        /// 流式解密
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始向量</param>
        public static void DecryptStream(Stream inputStream, Stream outputStream, string key,
            AESMode mode = AESMode.CBC, AESPadding padding = AESPadding.PKCS7, string iv = null)
        {
            byte[] keyBytes = ProcessKey(key);
            byte[] ivBytes = string.IsNullOrEmpty(iv) ? AES_IV : ProcessIV(iv);

            using (var aes = CreateAesProvider(keyBytes, ivBytes, mode, padding))
            {
                using (var decryptor = aes.CreateDecryptor())
                {
                    using (var cryptoStream = new CryptoStream(inputStream, decryptor, CryptoStreamMode.Read, true))
                    {
                        cryptoStream.CopyTo(outputStream);
                    }
                }
            }
        }

        #endregion

        #region 自定义填充实现

        /// <summary>
        /// 处理自定义填充的加密/解密
        /// </summary>
        /// <param name="data">数据</param>
        /// <param name="cryptoTransform">加密转换器</param>
        /// <param name="padding">填充模式</param>
        /// <param name="isDecrypt">是否为解密操作</param>
        /// <returns>处理后的数据</returns>
        private static byte[] ProcessCrypto(byte[] data, ICryptoTransform cryptoTransform, AESPadding padding, bool isDecrypt = true)
        {
            // 对于标准的.NET支持的填充模式，使用标准流处理
            if (padding == AESPadding.PKCS7 || padding == AESPadding.Zeros || padding == AESPadding.None)
            {
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }

            // 对于自定义填充模式，需要手动处理
            const int blockSize = 16; // AES块大小

            if (isDecrypt)
            {
                // 解密时，先解密再去除填充
                byte[] decryptedData;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cs.Write(data, 0, data.Length);
                        cs.FlushFinalBlock();
                        decryptedData = ms.ToArray();
                    }
                }

                return RemoveCustomPadding(decryptedData, padding);
            }
            else
            {
                // 加密时，先添加填充再加密
                byte[] paddedData = AddCustomPadding(data, padding, blockSize);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
                    {
                        cs.Write(paddedData, 0, paddedData.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        /// <summary>
        /// 添加自定义填充
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="padding">填充模式</param>
        /// <param name="blockSize">块大小</param>
        /// <returns>填充后的数据</returns>
        private static byte[] AddCustomPadding(byte[] data, AESPadding padding, int blockSize)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize) paddingLength = 0; // 数据长度已经是块大小的倍数

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            switch (padding)
            {
                case AESPadding.PKCS5:
                    // PKCS#5 填充：填充字节的值等于填充字节的数量
                    for (int i = data.Length; i < paddedData.Length; i++)
                    {
                        paddedData[i] = (byte)paddingLength;
                    }
                    break;

                case AESPadding.ISO10126:
                    // ISO 10126 填充：随机填充，最后一字节表示填充长度
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        if (paddingLength > 0)
                        {
                            byte[] randomBytes = new byte[paddingLength - 1];
                            rng.GetBytes(randomBytes);
                            Array.Copy(randomBytes, 0, paddedData, data.Length, paddingLength - 1);
                            paddedData[paddedData.Length - 1] = (byte)paddingLength;
                        }
                    }
                    break;

                case AESPadding.ANSIX923:
                    // ANSI X9.23 填充：填充字节为0，最后一字节表示填充长度
                    if (paddingLength > 0)
                    {
                        // 前面的填充字节已经是0（新数组默认为0）
                        paddedData[paddedData.Length - 1] = (byte)paddingLength;
                    }
                    break;

                default:
                    throw new NotSupportedException($"不支持的填充模式: {padding}");
            }

            return paddedData;
        }

        /// <summary>
        /// 移除自定义填充
        /// </summary>
        /// <param name="data">填充后的数据</param>
        /// <param name="padding">填充模式</param>
        /// <returns>移除填充后的数据</returns>
        private static byte[] RemoveCustomPadding(byte[] data, AESPadding padding)
        {
            if (data == null || data.Length == 0)
                return data;

            int paddingLength;

            switch (padding)
            {
                case AESPadding.PKCS5:
                    paddingLength = data[data.Length - 1];
                    // 验证填充的正确性
                    for (int i = data.Length - paddingLength; i < data.Length; i++)
                    {
                        if (data[i] != paddingLength)
                            throw new CryptographicException("无效的PKCS#5填充");
                    }
                    break;

                case AESPadding.ISO10126:
                case AESPadding.ANSIX923:
                    paddingLength = data[data.Length - 1];
                    break;

                default:
                    throw new NotSupportedException($"不支持的填充模式: {padding}");
            }

            if (paddingLength == 0 || paddingLength > data.Length)
                throw new CryptographicException($"无效的填充长度: {paddingLength}");

            byte[] result = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, result, 0, result.Length);
            return result;
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 创建AES加密提供程序
        /// </summary>
        private static Aes CreateAesProvider(byte[] key, byte[] iv, AESMode mode, AESPadding padding)
        {
            var aes = Aes.Create();
            aes.Key = key;

            // 设置加密模式
            try
            {
                aes.Mode = mode switch
                {
                    AESMode.ECB => CipherMode.ECB,
                    AESMode.CBC => CipherMode.CBC,
                    AESMode.CFB => CipherMode.CFB,
                    AESMode.OFB => CipherMode.OFB,
                    _ => CipherMode.CBC
                };
            }
            catch (CryptographicException)
            {
                // 如果OFB模式不支持，回退到CBC模式
                if (mode == AESMode.OFB)
                {
                    aes.Mode = CipherMode.CBC;
                    throw new NotSupportedException($"当前.NET版本不支持{mode}模式，请使用CBC、ECB或CFB模式");
                }
                throw;
            }

            // 设置填充模式
            aes.Padding = padding switch
            {
                AESPadding.PKCS7 => PaddingMode.PKCS7,
                AESPadding.PKCS5 => PaddingMode.PKCS7, // .NET中PKCS5等同于PKCS7
                AESPadding.Zeros => PaddingMode.Zeros,
                AESPadding.None => PaddingMode.None,
                // 自定义填充模式设置为None，由我们手动处理
                AESPadding.ISO10126 => PaddingMode.None,
                AESPadding.ANSIX923 => PaddingMode.None,
                _ => PaddingMode.PKCS7
            };

            // ECB模式不需要IV
            if (mode != AESMode.ECB && iv != null)
            {
                aes.IV = iv;
            }

            return aes;
        }

        /// <summary>
        /// 处理密钥，确保长度正确
        /// </summary>
        public static byte[] ProcessKey(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            byte[] keyBytes;

            // 尝试Base64解码
            try
            {
                keyBytes = Convert.FromBase64String(key);
            }
            catch
            {
                // 如果不是Base64，则直接使用UTF8编码
                keyBytes = Encoding.UTF8.GetBytes(key);
            }

            // 调整密钥长度到有效的AES密钥长度
            if (keyBytes.Length <= 16)
            {
                Array.Resize(ref keyBytes, 16); // 128位
            }
            else if (keyBytes.Length <= 24)
            {
                Array.Resize(ref keyBytes, 24); // 192位
            }
            else
            {
                Array.Resize(ref keyBytes, 32); // 256位
            }

            return keyBytes;
        }

        /// <summary>
        /// 处理初始向量，确保长度为16字节
        /// </summary>
        public static byte[] ProcessIV(string iv)
        {
            if (string.IsNullOrEmpty(iv))
                return AES_IV;

            byte[] ivBytes;

            // 尝试Base64解码
            try
            {
                ivBytes = Convert.FromBase64String(iv);
            }
            catch
            {
                // 如果不是Base64，则直接使用UTF8编码
                ivBytes = Encoding.UTF8.GetBytes(iv);
            }

            // 调整IV长度到16字节
            Array.Resize(ref ivBytes, 16);
            return ivBytes;
        }

        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        private static byte[] HexStringToByteArray(string hex)
        {
            // 移除连字符
            hex = hex.Replace("-", "");

            if (hex.Length % 2 != 0)
                throw new ArgumentException("十六进制字符串长度必须为偶数", nameof(hex));

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber);
            }
            return bytes;
        }

        /// <summary>
        /// 验证密钥长度是否有效
        /// </summary>
        public static bool IsValidKeySize(int keySize)
        {
            return keySize == 128 || keySize == 192 || keySize == 256;
        }

        /// <summary>
        /// 获取密钥强度描述
        /// </summary>
        public static string GetKeyStrengthDescription(byte[] key)
        {
            if (key == null) return "无效密钥";

            return key.Length switch
            {
                16 => "AES-128（标准强度）",
                24 => "AES-192（高强度）",
                32 => "AES-256（最高强度）",
                _ => $"非标准密钥长度（{key.Length * 8}位）"
            };
        }

        /// <summary>
        /// 获取填充模式描述
        /// </summary>
        /// <param name="padding">填充模式</param>
        /// <returns>填充模式描述</returns>
        public static string GetPaddingDescription(AESPadding padding)
        {
            return padding switch
            {
                AESPadding.PKCS7 => "PKCS#7 - 标准填充模式（推荐）",
                AESPadding.PKCS5 => "PKCS#5 - 与PKCS#7相同，用于8字节块",
                AESPadding.Zeros => "零填充 - 使用零字节填充",
                AESPadding.ISO10126 => "ISO 10126 - 随机填充，最后字节为长度",
                AESPadding.ANSIX923 => "ANSI X9.23 - 零填充，最后字节为长度",
                AESPadding.None => "无填充 - 数据长度必须是块大小倍数",
                _ => "未知填充模式"
            };
        }

        /// <summary>
        /// 验证填充模式是否受支持
        /// </summary>
        /// <param name="padding">填充模式</param>
        /// <returns>是否支持</returns>
        public static bool IsPaddingSupportedNatively(AESPadding padding)
        {
            return padding switch
            {
                AESPadding.PKCS7 => true,
                AESPadding.PKCS5 => true, // 在.NET中等同于PKCS7
                AESPadding.Zeros => true,
                AESPadding.None => true,
                AESPadding.ISO10126 => false, // 需要自定义实现
                AESPadding.ANSIX923 => false, // 需要自定义实现
                _ => false
            };
        }

        #endregion
    }
}