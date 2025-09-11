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
    /// DES对称加密工具类
    /// 提供字符串、文件、流的DES加密解密功能
    /// 支持多种加密模式、填充方式和输出格式
    /// </summary>
    public static class DESUtil
    {
        #region 枚举定义

        /// <summary>
        /// DES加密模式
        /// </summary>
        public enum DESMode
        {
            /// <summary>
            /// 电子密码本模式 (Electronic Codebook)
            /// </summary>
            ECB,
            /// <summary>
            /// 密码块链模式 (Cipher Block Chaining)
            /// </summary>
            CBC,
            /// <summary>
            /// 密码反馈模式 (Cipher Feedback)
            /// </summary>
            CFB,
            /// <summary>
            /// 输出反馈模式 (Output Feedback)
            /// </summary>
            OFB
        }

        /// <summary>
        /// DES填充模式
        /// </summary>
        public enum DESPadding
        {
            /// <summary>
            /// PKCS7填充
            /// </summary>
            PKCS7,
            /// <summary>
            /// PKCS5填充 - 与PKCS7类似，但专门用于8字节块大小
            /// </summary>
            PKCS5,
            /// <summary>
            /// 零填充
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
            /// 无填充
            /// </summary>
            None
        }

        /// <summary>
        /// 输出格式
        /// </summary>
        public enum OutputFormat
        {
            /// <summary>
            /// Base64编码
            /// </summary>
            Base64,
            /// <summary>
            /// 16进制字符串
            /// </summary>
            Hex
        }

        #endregion

        #region 字符串DES加解密

        /// <summary>
        /// DES加密（简化版本，使用默认参数）
        /// </summary>
        /// <param name="input">待加密的字符串</param>
        /// <param name="key">密钥（8字节）</param>
        /// <returns>Base64编码的加密结果</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static string EncryptByDES(string input, string key)
        {
            return EncryptByDES(input, key, DESMode.CBC, DESPadding.PKCS7, OutputFormat.Base64);
        }

        /// <summary>
        /// DES加密（完整版本）
        /// </summary>
        /// <param name="input">待加密的字符串</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="iv">初始化向量（8字节），ECB模式时可为null</param>
        /// <returns>加密结果</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static string EncryptByDES(string input, string key, DESMode mode = DESMode.CBC, 
            DESPadding padding = DESPadding.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("待加密字符串不能为空", nameof(input));
            
            ValidateKey(key);

            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;

            if (mode != DESMode.ECB)
            {
                if (string.IsNullOrEmpty(iv))
                    iv = key; // 默认使用密钥作为IV
                ivBytes = Encoding.UTF8.GetBytes(iv);
                ValidateIV(ivBytes);
            }

            byte[] encryptedBytes = EncryptByDES(inputBytes, keyBytes, mode, padding, ivBytes);

            return outputFormat == OutputFormat.Base64 
                ? Convert.ToBase64String(encryptedBytes)
                : ConvertToHexString(encryptedBytes);
        }

        /// <summary>
        /// DES解密（简化版本，使用默认参数）
        /// </summary>
        /// <param name="input">待解密的字符串（Base64编码）</param>
        /// <param name="key">密钥（8字节）</param>
        /// <returns>解密后的字符串</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static string DecryptByDES(string input, string key)
        {
            return DecryptByDES(input, key, DESMode.CBC, DESPadding.PKCS7, OutputFormat.Base64);
        }

        /// <summary>
        /// DES解密（完整版本）
        /// </summary>
        /// <param name="input">待解密的字符串</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="iv">初始化向量（8字节），ECB模式时可为null</param>
        /// <returns>解密后的字符串</returns>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static string DecryptByDES(string input, string key, DESMode mode = DESMode.CBC,
            DESPadding padding = DESPadding.PKCS7, OutputFormat inputFormat = OutputFormat.Base64, string iv = null)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("待解密字符串不能为空", nameof(input));

            ValidateKey(key);

            byte[] inputBytes = inputFormat == OutputFormat.Base64
                ? Convert.FromBase64String(input)
                : ConvertFromHexString(input);

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;

            if (mode != DESMode.ECB)
            {
                if (string.IsNullOrEmpty(iv))
                    iv = key; // 默认使用密钥作为IV
                ivBytes = Encoding.UTF8.GetBytes(iv);
                ValidateIV(ivBytes);
            }

            byte[] decryptedBytes = DecryptByDES(inputBytes, keyBytes, mode, padding, ivBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// DES加密字节数组
        /// </summary>
        /// <param name="inputBytes">待加密的字节数组</param>
        /// <param name="keyBytes">密钥字节数组（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="ivBytes">初始化向量字节数组（8字节），ECB模式时可为null</param>
        /// <returns>加密后的字节数组</returns>
        public static byte[] EncryptByDES(byte[] inputBytes, byte[] keyBytes, DESMode mode = DESMode.CBC,
            DESPadding padding = DESPadding.PKCS7, byte[] ivBytes = null)
        {
            if (inputBytes == null || inputBytes.Length == 0)
                throw new ArgumentException("待加密数据不能为空", nameof(inputBytes));

            ValidateKey(keyBytes);

            if (mode != DESMode.ECB && ivBytes != null)
                ValidateIV(ivBytes);

            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = keyBytes;
                des.Mode = ConvertToCipherMode(mode);
                des.Padding = ConvertToPaddingMode(padding);

                if (mode != DESMode.ECB && ivBytes != null)
                    des.IV = ivBytes;

                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(inputBytes, 0, inputBytes.Length);
                        cryptoStream.FlushFinalBlock();
                    }
                    return memoryStream.ToArray();
                }
            }
        }

        /// <summary>
        /// DES解密字节数组
        /// </summary>
        /// <param name="inputBytes">待解密的字节数组</param>
        /// <param name="keyBytes">密钥字节数组（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="ivBytes">初始化向量字节数组（8字节），ECB模式时可为null</param>
        /// <returns>解密后的字节数组</returns>
        public static byte[] DecryptByDES(byte[] inputBytes, byte[] keyBytes, DESMode mode = DESMode.CBC,
            DESPadding padding = DESPadding.PKCS7, byte[] ivBytes = null)
        {
            if (inputBytes == null || inputBytes.Length == 0)
                throw new ArgumentException("待解密数据不能为空", nameof(inputBytes));

            ValidateKey(keyBytes);

            if (mode != DESMode.ECB && ivBytes != null)
                ValidateIV(ivBytes);

            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = keyBytes;
                des.Mode = ConvertToCipherMode(mode);
                des.Padding = ConvertToPaddingMode(padding);

                if (mode != DESMode.ECB && ivBytes != null)
                    des.IV = ivBytes;

                using (var memoryStream = new MemoryStream(inputBytes))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (var resultStream = new MemoryStream())
                        {
                            cryptoStream.CopyTo(resultStream);
                            return resultStream.ToArray();
                        }
                    }
                }
            }
        }

        #endregion

        #region 文件DES加解密

        /// <summary>
        /// 加密文件
        /// </summary>
        /// <param name="inputFilePath">源文件路径</param>
        /// <param name="outputFilePath">加密后文件路径</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量，ECB模式时可为null</param>
        /// <exception cref="FileNotFoundException">文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static void EncryptFile(string inputFilePath, string outputFilePath, string key,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, string iv = null)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("源文件路径不能为空", nameof(inputFilePath));

            if (string.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("目标文件路径不能为空", nameof(outputFilePath));

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"源文件不存在: {inputFilePath}");

            ValidateKey(key);

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;

            if (mode != DESMode.ECB)
            {
                if (string.IsNullOrEmpty(iv))
                    iv = key;
                ivBytes = Encoding.UTF8.GetBytes(iv);
                ValidateIV(ivBytes);
            }

            using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                EncryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
            }
        }

        /// <summary>
        /// 解密文件
        /// </summary>
        /// <param name="inputFilePath">加密文件路径</param>
        /// <param name="outputFilePath">解密后文件路径</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量，ECB模式时可为null</param>
        /// <exception cref="FileNotFoundException">文件不存在时抛出</exception>
        /// <exception cref="ArgumentException">参数无效时抛出</exception>
        public static void DecryptFile(string inputFilePath, string outputFilePath, string key,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, string iv = null)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("源文件路径不能为空", nameof(inputFilePath));

            if (string.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("目标文件路径不能为空", nameof(outputFilePath));

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"源文件不存在: {inputFilePath}");

            ValidateKey(key);

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] ivBytes = null;

            if (mode != DESMode.ECB)
            {
                if (string.IsNullOrEmpty(iv))
                    iv = key;
                ivBytes = Encoding.UTF8.GetBytes(iv);
                ValidateIV(ivBytes);
            }

            using (var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
            using (var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
            {
                DecryptStream(inputStream, outputStream, keyBytes, mode, padding, ivBytes);
            }
        }

        #endregion

        #region 流DES加解密

        /// <summary>
        /// 加密流
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="keyBytes">密钥字节数组（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="ivBytes">初始化向量字节数组（8字节），ECB模式时可为null</param>
        public static void EncryptStream(Stream inputStream, Stream outputStream, byte[] keyBytes,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, byte[] ivBytes = null)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            ValidateKey(keyBytes);

            if (mode != DESMode.ECB && ivBytes != null)
                ValidateIV(ivBytes);

            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = keyBytes;
                des.Mode = ConvertToCipherMode(mode);
                des.Padding = ConvertToPaddingMode(padding);

                if (mode != DESMode.ECB && ivBytes != null)
                    des.IV = ivBytes;

                using (var cryptoStream = new CryptoStream(outputStream, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    inputStream.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                }
            }
        }

        /// <summary>
        /// 解密流
        /// </summary>
        /// <param name="inputStream">输入流</param>
        /// <param name="outputStream">输出流</param>
        /// <param name="keyBytes">密钥字节数组（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="ivBytes">初始化向量字节数组（8字节），ECB模式时可为null</param>
        public static void DecryptStream(Stream inputStream, Stream outputStream, byte[] keyBytes,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, byte[] ivBytes = null)
        {
            if (inputStream == null)
                throw new ArgumentNullException(nameof(inputStream));

            if (outputStream == null)
                throw new ArgumentNullException(nameof(outputStream));

            ValidateKey(keyBytes);

            if (mode != DESMode.ECB && ivBytes != null)
                ValidateIV(ivBytes);

            using (var des = new DESCryptoServiceProvider())
            {
                des.Key = keyBytes;
                des.Mode = ConvertToCipherMode(mode);
                des.Padding = ConvertToPaddingMode(padding);

                if (mode != DESMode.ECB && ivBytes != null)
                    des.IV = ivBytes;

                using (var cryptoStream = new CryptoStream(inputStream, des.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(outputStream);
                }
            }
        }

        #endregion

        #region 异步操作

        /// <summary>
        /// 异步加密文件
        /// </summary>
        /// <param name="inputFilePath">源文件路径</param>
        /// <param name="outputFilePath">加密后文件路径</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量，ECB模式时可为null</param>
        /// <returns>异步任务</returns>
        public static async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string key,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, string iv = null)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 异步解密文件
        /// </summary>
        /// <param name="inputFilePath">加密文件路径</param>
        /// <param name="outputFilePath">解密后文件路径</param>
        /// <param name="key">密钥（8字节）</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量，ECB模式时可为null</param>
        /// <returns>异步任务</returns>
        public static async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, string iv = null)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        #endregion

        #region 密钥生成

        /// <summary>
        /// 生成DES密钥（8字节）
        /// </summary>
        /// <param name="format">输出格式</param>
        /// <returns>DES密钥</returns>
        public static string GenerateKey(OutputFormat format = OutputFormat.Base64)
        {
            byte[] keyBytes = new byte[8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(keyBytes);
            }

            return format == OutputFormat.Base64
                ? Convert.ToBase64String(keyBytes)
                : ConvertToHexString(keyBytes);
        }

        /// <summary>
        /// 生成DES初始化向量（8字节）
        /// </summary>
        /// <param name="format">输出格式</param>
        /// <returns>DES初始化向量</returns>
        public static string GenerateIV(OutputFormat format = OutputFormat.Base64)
        {
            byte[] ivBytes = new byte[8];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(ivBytes);
            }

            return format == OutputFormat.Base64
                ? Convert.ToBase64String(ivBytes)
                : ConvertToHexString(ivBytes);
        }

        #endregion

        #region 验证方法

        /// <summary>
        /// 验证DES加密解密结果
        /// </summary>
        /// <param name="originalText">原始文本</param>
        /// <param name="encryptedText">加密文本</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>验证结果</returns>
        public static bool VerifyDES(string originalText, string encryptedText, string key,
            DESMode mode = DESMode.CBC, DESPadding padding = DESPadding.PKCS7, 
            OutputFormat inputFormat = OutputFormat.Base64, string iv = null)
        {
            try
            {
                string decryptedText = DecryptByDES(encryptedText, key, mode, padding, inputFormat, iv);
                return string.Equals(originalText, decryptedText, StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        #endregion


        #region 私有辅助方法

        /// <summary>
        /// 验证密钥有效性
        /// </summary>
        /// <param name="key">密钥字符串</param>
        private static void ValidateKey(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            ValidateKey(keyBytes);
        }

        /// <summary>
        /// 验证密钥字节数组有效性
        /// </summary>
        /// <param name="keyBytes">密钥字节数组</param>
        private static void ValidateKey(byte[] keyBytes)
        {
            if (keyBytes == null)
                throw new ArgumentNullException(nameof(keyBytes));

            if (keyBytes.Length != 8)
                throw new ArgumentException("DES密钥必须为8字节", nameof(keyBytes));
        }

        /// <summary>
        /// 验证初始化向量有效性
        /// </summary>
        /// <param name="ivBytes">初始化向量字节数组</param>
        private static void ValidateIV(byte[] ivBytes)
        {
            if (ivBytes == null)
                throw new ArgumentNullException(nameof(ivBytes));

            if (ivBytes.Length != 8)
                throw new ArgumentException("DES初始化向量必须为8字节", nameof(ivBytes));
        }

        /// <summary>
        /// 转换为.NET的CipherMode
        /// </summary>
        /// <param name="mode">DES模式</param>
        /// <returns>.NET的CipherMode</returns>
        private static CipherMode ConvertToCipherMode(DESMode mode)
        {
            return mode switch
            {
                DESMode.ECB => CipherMode.ECB,
                DESMode.CBC => CipherMode.CBC,
                DESMode.CFB => CipherMode.CFB,
                DESMode.OFB => CipherMode.OFB,
                _ => CipherMode.CBC
            };
        }

        /// <summary>
        /// 转换为.NET的PaddingMode
        /// </summary>
        /// <param name="padding">DES填充模式</param>
        /// <returns>.NET的PaddingMode</returns>
        private static PaddingMode ConvertToPaddingMode(DESPadding padding)
        {
            return padding switch
            {
                DESPadding.PKCS7 => PaddingMode.PKCS7,
                DESPadding.PKCS5 => PaddingMode.PKCS7, // .NET中PKCS5等同于PKCS7
                DESPadding.Zeros => PaddingMode.Zeros,
                DESPadding.ISO10126 => PaddingMode.ISO10126,
                DESPadding.ANSIX923 => PaddingMode.ANSIX923,
                DESPadding.None => PaddingMode.None,
                _ => PaddingMode.PKCS7
            };
        }

        /// <summary>
        /// 将字节数组转换为16进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>16进制字符串</returns>
        private static string ConvertToHexString(byte[] bytes, bool upperCase = false)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            string format = upperCase ? "X2" : "x2";

            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString(format));
            }

            return sb.ToString();
        }

        /// <summary>
        /// 将16进制字符串转换为字节数组
        /// </summary>
        /// <param name="hexString">16进制字符串</param>
        /// <returns>字节数组</returns>
        private static byte[] ConvertFromHexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("16进制字符串不能为空", nameof(hexString));

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("16进制字符串长度必须为偶数", nameof(hexString));

            byte[] result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return result;
        }

        #endregion
    }
}
