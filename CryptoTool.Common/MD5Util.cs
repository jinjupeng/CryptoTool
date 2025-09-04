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
    /// MD5加密和哈希计算工具类
    /// 提供字符串、文件、流的MD5哈希计算功能
    /// </summary>
    public static class MD5Util
    {
        #region 字符串MD5加密

        /// <summary>
        /// MD5加密为32字符长度的16进制字符串（小写）
        /// </summary>
        /// <param name="input">待加密的字符串</param>
        /// <param name="encoding">字符编码，默认UTF-8</param>
        /// <returns>32位小写16进制MD5哈希值</returns>
        /// <exception cref="ArgumentNullException">输入字符串为null时抛出</exception>
        public static string EncryptByMD5(string input, Encoding encoding = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            encoding = encoding ?? Encoding.UTF8;
            
            using (var md5 = MD5.Create())
            {
                byte[] inputBytes = encoding.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return ConvertToHexString(hashBytes, false);
            }
        }

        /// <summary>
        /// MD5加密为32字符长度的16进制字符串（大写）
        /// </summary>
        /// <param name="input">待加密的字符串</param>
        /// <param name="encoding">字符编码，默认UTF-8</param>
        /// <returns>32位大写16进制MD5哈希值</returns>
        /// <exception cref="ArgumentNullException">输入字符串为null时抛出</exception>
        public static string EncryptByMD5Upper(string input, Encoding encoding = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            encoding = encoding ?? Encoding.UTF8;
            
            using (var md5 = MD5.Create())
            {
                byte[] inputBytes = encoding.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return ConvertToHexString(hashBytes, true);
            }
        }

        /// <summary>
        /// 计算字符串的MD5哈希值（字节数组形式）
        /// </summary>
        /// <param name="input">待计算的字符串</param>
        /// <param name="encoding">字符编码，默认UTF-8</param>
        /// <returns>MD5哈希值字节数组</returns>
        /// <exception cref="ArgumentNullException">输入字符串为null时抛出</exception>
        public static byte[] ComputeMD5Hash(string input, Encoding encoding = null)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            encoding = encoding ?? Encoding.UTF8;
            
            using (var md5 = MD5.Create())
            {
                byte[] inputBytes = encoding.GetBytes(input);
                return md5.ComputeHash(inputBytes);
            }
        }

        /// <summary>
        /// 计算字节数组的MD5哈希值
        /// </summary>
        /// <param name="input">待计算的字节数组</param>
        /// <returns>MD5哈希值字节数组</returns>
        /// <exception cref="ArgumentNullException">输入字节数组为null时抛出</exception>
        public static byte[] ComputeMD5Hash(byte[] input)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(input);
            }
        }

        /// <summary>
        /// 计算字符串的MD5哈希值并返回Base64编码
        /// </summary>
        /// <param name="input">待计算的字符串</param>
        /// <param name="encoding">字符编码，默认UTF-8</param>
        /// <returns>Base64编码的MD5哈希值</returns>
        /// <exception cref="ArgumentNullException">输入字符串为null时抛出</exception>
        public static string EncryptByMD5ToBase64(string input, Encoding encoding = null)
        {
            byte[] hashBytes = ComputeMD5Hash(input, encoding);
            return Convert.ToBase64String(hashBytes);
        }

        #endregion

        #region 文件MD5计算

        /// <summary>
        /// 获取文件的哈希值（支持多种算法）
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="hashAlgo">哈希算法名称，默认为MD5，支持：MD5、SHA1、SHA256、SHA384、SHA512</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>文件哈希值的16进制字符串，计算失败返回空字符串</returns>
        public static string GetFileHashCode(string filePath, string hashAlgo = "MD5", bool upperCase = false)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return string.Empty;

            if (!File.Exists(filePath))
                return string.Empty;

            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var hashAlgorithm = HashAlgorithm.Create(hashAlgo))
                {
                    if (hashAlgorithm == null)
                        throw new NotSupportedException($"不支持的哈希算法: {hashAlgo}");

                    byte[] hashBytes = hashAlgorithm.ComputeHash(fileStream);
                    return ConvertToHexString(hashBytes, upperCase);
                }
            }
            catch (Exception ex)
            {
                // 记录异常信息（实际项目中应使用日志框架）
                Console.WriteLine($"计算文件哈希失败: {ex.Message}");
                return string.Empty;
            }
        }

        /// <summary>
        /// 异步获取文件的MD5哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>文件MD5哈希值的16进制字符串</returns>
        /// <exception cref="ArgumentException">文件路径为空或文件不存在时抛出</exception>
        /// <exception cref="IOException">文件读取失败时抛出</exception>
        public static async Task<string> GetFileMD5Async(string filePath, bool upperCase = false)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                throw new ArgumentException("文件路径不能为空", nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"文件不存在: {filePath}");

            try
            {
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true))
                using (var md5 = MD5.Create())
                {
                    byte[] hashBytes = await ComputeHashAsync(md5, fileStream);
                    return ConvertToHexString(hashBytes, upperCase);
                }
            }
            catch (Exception ex)
            {
                throw new IOException($"计算文件MD5失败: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// 比较两个文件的MD5哈希值是否相同
        /// </summary>
        /// <param name="filePath1">第一个文件路径</param>
        /// <param name="filePath2">第二个文件路径</param>
        /// <returns>如果两个文件的MD5哈希值相同返回true，否则返回false</returns>
        public static bool CompareFileMD5(string filePath1, string filePath2)
        {
            if (string.IsNullOrWhiteSpace(filePath1) || string.IsNullOrWhiteSpace(filePath2))
                return false;

            if (!File.Exists(filePath1) || !File.Exists(filePath2))
                return false;

            string hash1 = GetFileHashCode(filePath1, "MD5");
            string hash2 = GetFileHashCode(filePath2, "MD5");

            return !string.IsNullOrEmpty(hash1) && !string.IsNullOrEmpty(hash2) && 
                   string.Equals(hash1, hash2, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 异步比较两个文件的MD5哈希值是否相同
        /// </summary>
        /// <param name="filePath1">第一个文件路径</param>
        /// <param name="filePath2">第二个文件路径</param>
        /// <returns>如果两个文件的MD5哈希值相同返回true，否则返回false</returns>
        public static async Task<bool> CompareFileMD5Async(string filePath1, string filePath2)
        {
            if (string.IsNullOrWhiteSpace(filePath1) || string.IsNullOrWhiteSpace(filePath2))
                return false;

            if (!File.Exists(filePath1) || !File.Exists(filePath2))
                return false;

            try
            {
                var task1 = GetFileMD5Async(filePath1);
                var task2 = GetFileMD5Async(filePath2);

                await Task.WhenAll(task1, task2);

                return string.Equals(task1.Result, task2.Result, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 流MD5计算

        /// <summary>
        /// 计算流的MD5哈希值
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>MD5哈希值的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">流为null时抛出</exception>
        public static string ComputeStreamMD5(Stream stream, bool upperCase = false)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(stream);
                return ConvertToHexString(hashBytes, upperCase);
            }
        }

        /// <summary>
        /// 异步计算流的MD5哈希值
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>MD5哈希值的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">流为null时抛出</exception>
        public static async Task<string> ComputeStreamMD5Async(Stream stream, bool upperCase = false)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = await ComputeHashAsync(md5, stream);
                return ConvertToHexString(hashBytes, upperCase);
            }
        }

        #endregion

        #region MD5验证

        /// <summary>
        /// 验证字符串的MD5哈希值是否正确
        /// </summary>
        /// <param name="input">原始字符串</param>
        /// <param name="expectedHash">期望的MD5哈希值</param>
        /// <param name="encoding">字符编码，默认UTF-8</param>
        /// <returns>如果哈希值匹配返回true，否则返回false</returns>
        public static bool VerifyMD5(string input, string expectedHash, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(expectedHash))
                return false;

            try
            {
                string actualHash = EncryptByMD5(input, encoding);
                return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 验证文件的MD5哈希值是否正确
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="expectedHash">期望的MD5哈希值</param>
        /// <returns>如果哈希值匹配返回true，否则返回false</returns>
        public static bool VerifyFileMD5(string filePath, string expectedHash)
        {
            if (string.IsNullOrEmpty(filePath) || string.IsNullOrEmpty(expectedHash))
                return false;

            try
            {
                string actualHash = GetFileHashCode(filePath, "MD5");
                return string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 工具方法

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
        /// 异步计算哈希值的辅助方法
        /// </summary>
        /// <param name="hashAlgorithm">哈希算法实例</param>
        /// <param name="stream">输入流</param>
        /// <returns>哈希值字节数组</returns>
        private static async Task<byte[]> ComputeHashAsync(HashAlgorithm hashAlgorithm, Stream stream)
        {
            const int bufferSize = 4096;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while ((bytesRead = await stream.ReadAsync(buffer, 0, bufferSize)) > 0)
            {
                hashAlgorithm.TransformBlock(buffer, 0, bytesRead, null, 0);
            }

            hashAlgorithm.TransformFinalBlock(buffer, 0, 0);
            return hashAlgorithm.Hash;
        }

        /// <summary>
        /// 将16进制字符串分隔的字节数组转换为字节数组
        /// </summary>
        /// <param name="input">以"-"分隔的16进制字符串</param>
        /// <returns>字节数组</returns>
        /// <exception cref="ArgumentException">输入格式不正确时抛出</exception>
        public static byte[] GetBytesFromHexString(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException("输入字符串不能为空", nameof(input));

            try
            {
                string[] hexStrings = input.Split('-');
                byte[] result = new byte[hexStrings.Length];
                
                for (int i = 0; i < hexStrings.Length; i++)
                {
                    result[i] = byte.Parse(hexStrings[i], NumberStyles.HexNumber);
                }
                
                return result;
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"无效的16进制字符串格式: {input}", nameof(input), ex);
            }
        }

        /// <summary>
        /// 将字节数组转换为以"-"分隔的16进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>以"-"分隔的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">字节数组为null时抛出</exception>
        public static string GetHexStringFromBytes(byte[] bytes, bool upperCase = false)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            string format = upperCase ? "X2" : "x2";
            return string.Join("-", bytes.Select(b => b.ToString(format)));
        }

        #endregion

        #region API密钥生成

        /// <summary>
        /// 生成API密钥（appId）
        /// </summary>
        /// <param name="keyLength">密钥长度（字节数），默认32字节</param>
        /// <returns>Base64编码的API密钥</returns>
        public static string GenerateAppId(int keyLength = 32)
        {
            if (keyLength <= 0)
                throw new ArgumentException("密钥长度必须大于0", nameof(keyLength));

            var key = new byte[keyLength];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(key);
            }
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// 生成API密钥（appSecret）
        /// </summary>
        /// <param name="keyLength">密钥长度（字节数），默认64字节</param>
        /// <returns>Base64编码的API密钥</returns>
        public static string GenerateAppSecret(int keyLength = 64)
        {
            if (keyLength <= 0)
                throw new ArgumentException("密钥长度必须大于0", nameof(keyLength));

            var key = new byte[keyLength];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(key);
            }
            return Convert.ToBase64String(key);
        }

        /// <summary>
        /// 生成16进制格式的随机密钥
        /// </summary>
        /// <param name="keyLength">密钥长度（字节数），默认16字节</param>
        /// <param name="upperCase">是否返回大写，默认false（小写）</param>
        /// <returns>16进制格式的密钥</returns>
        public static string GenerateHexKey(int keyLength = 16, bool upperCase = false)
        {
            if (keyLength <= 0)
                throw new ArgumentException("密钥长度必须大于0", nameof(keyLength));

            var key = new byte[keyLength];
            using (var generator = RandomNumberGenerator.Create())
            {
                generator.GetBytes(key);
            }
            return ConvertToHexString(key, upperCase);
        }

        #endregion

    }
}
