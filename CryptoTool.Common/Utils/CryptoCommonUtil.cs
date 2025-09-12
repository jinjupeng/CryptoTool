using CryptoTool.Common.Enums;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common.Utils
{
    /// <summary>
    /// 加密通用工具类
    /// </summary>
    public static class CryptoCommonUtil
    {
        #region 基础字节数组转换方法

        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        /// <param name="hexString">十六进制字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] ConvertFromHexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("十六进制字符串不能为空", nameof(hexString));

            // 移除连字符和空格
            hexString = hexString.Replace("-", "").Replace(" ", "");

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("十六进制字符串长度必须为偶数", nameof(hexString));

            byte[] bytes = new byte[hexString.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// 字节数组转十六进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>十六进制字符串</returns>
        public static string ConvertToHexString(byte[] bytes, bool upperCase = false)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            string format = upperCase ? "X2" : "x2";
            StringBuilder sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                sb.Append(b.ToString(format));
            }
            return sb.ToString();
        }

        #endregion

        #region 密钥处理方法

        /// <summary>
        /// 处理密钥，确保长度正确
        /// </summary>
        /// <param name="key">密钥字符串</param>
        /// <param name="keySize">期望的密钥长度（字节）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>处理后的密钥字节数组</returns>
        public static byte[] ProcessKey(string key, int keySize, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            encoding = encoding ?? Encoding.UTF8;
            byte[] keyBytes = encoding.GetBytes(key);

            // 调整密钥长度
            if (keyBytes.Length < keySize)
            {
                // 密钥太短，使用哈希扩展
                using (var sha256 = SHA256.Create())
                {
                    keyBytes = sha256.ComputeHash(keyBytes);
                }
            }

            // 截取或填充到指定长度
            Array.Resize(ref keyBytes, keySize);
            return keyBytes;
        }

        /// <summary>
        /// 处理初始化向量，确保长度正确
        /// </summary>
        /// <param name="iv">初始化向量字符串</param>
        /// <param name="ivSize">期望的IV长度（字节）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>处理后的IV字节数组</returns>
        public static byte[] ProcessIV(string iv, int ivSize, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(iv))
            {
                // 生成随机IV
                byte[] randomIV = new byte[ivSize];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(randomIV);
                }
                return randomIV;
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] ivBytes = encoding.GetBytes(iv);
            Array.Resize(ref ivBytes, ivSize);
            return ivBytes;
        }

        #endregion

        #region 随机数生成

        /// <summary>
        /// 生成随机字节数组
        /// </summary>
        /// <param name="length">长度</param>
        /// <returns>随机字节数组</returns>
        public static byte[] GenerateRandomBytes(int length)
        {
            if (length <= 0)
                throw new ArgumentException("长度必须大于0", nameof(length));

            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        /// <summary>
        /// 生成随机字符串
        /// </summary>
        /// <param name="length">长度</param>
        /// <param name="charset">字符集</param>
        /// <returns>随机字符串</returns>
        public static string GenerateRandomString(int length, string charset = null)
        {
            if (length <= 0)
                throw new ArgumentException("长度必须大于0", nameof(length));

            charset = charset ?? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            StringBuilder sb = new StringBuilder(length);
            byte[] randomBytes = GenerateRandomBytes(length);

            for (int i = 0; i < length; i++)
            {
                sb.Append(charset[randomBytes[i] % charset.Length]);
            }

            return sb.ToString();
        }

        #endregion

        #region 验证方法

        /// <summary>
        /// 验证密钥长度
        /// </summary>
        /// <param name="keyBytes">密钥字节数组</param>
        /// <param name="expectedLength">期望长度</param>
        /// <param name="algorithmType">算法类型</param>
        /// <returns>是否有效</returns>
        public static bool ValidateKeyLength(byte[] keyBytes, int expectedLength, AlgorithmType algorithmType)
        {
            if (keyBytes == null)
                return false;

            return keyBytes.Length == expectedLength;
        }

        /// <summary>
        /// 验证IV长度
        /// </summary>
        /// <param name="ivBytes">IV字节数组</param>
        /// <param name="expectedLength">期望长度</param>
        /// <returns>是否有效</returns>
        public static bool ValidateIVLength(byte[] ivBytes, int expectedLength)
        {
            if (ivBytes == null)
                return false;

            return ivBytes.Length == expectedLength;
        }

        #endregion

        #region 填充处理

        /// <summary>
        /// 添加PKCS7填充
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="blockSize">块大小</param>
        /// <returns>填充后的数据</returns>
        public static byte[] AddPKCS7Padding(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            int paddingLength = blockSize - data.Length % blockSize;
            if (paddingLength == blockSize) paddingLength = 0;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            for (int i = data.Length; i < paddedData.Length; i++)
            {
                paddedData[i] = (byte)paddingLength;
            }

            return paddedData;
        }

        /// <summary>
        /// 移除PKCS7填充
        /// </summary>
        /// <param name="data">填充后的数据</param>
        /// <returns>移除填充后的数据</returns>
        public static byte[] RemovePKCS7Padding(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            int paddingLength = data[data.Length - 1];
            if (paddingLength == 0 || paddingLength > data.Length)
                throw new CryptographicException("无效的PKCS7填充");

            // 验证填充的正确性
            for (int i = data.Length - paddingLength; i < data.Length; i++)
            {
                if (data[i] != paddingLength)
                    throw new CryptographicException("无效的PKCS7填充");
            }

            byte[] result = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, result, 0, result.Length);
            return result;
        }

        /// <summary>
        /// 添加零填充
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="blockSize">块大小</param>
        /// <returns>填充后的数据</returns>
        public static byte[] AddZeroPadding(byte[] data, int blockSize)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            int paddingLength = blockSize - data.Length % blockSize;
            if (paddingLength == blockSize) paddingLength = 0;

            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);
            // 其余字节默认为0

            return paddedData;
        }

        /// <summary>
        /// 移除零填充
        /// </summary>
        /// <param name="data">填充后的数据</param>
        /// <returns>移除填充后的数据</returns>
        public static byte[] RemoveZeroPadding(byte[] data)
        {
            if (data == null || data.Length == 0)
                return data;

            // 从末尾开始查找非零字节
            int endIndex = data.Length - 1;
            while (endIndex >= 0 && data[endIndex] == 0)
            {
                endIndex--;
            }

            if (endIndex < 0)
                return new byte[0]; // 全部为零

            byte[] result = new byte[endIndex + 1];
            Array.Copy(data, 0, result, 0, result.Length);
            return result;
        }

        #endregion

        #region 文件操作

        /// <summary>
        /// 安全地复制流
        /// </summary>
        /// <param name="source">源流</param>
        /// <param name="destination">目标流</param>
        /// <param name="bufferSize">缓冲区大小</param>
        public static void SafeCopyStream(Stream source, Stream destination, int bufferSize = 8192)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));
            if (destination == null)
                throw new ArgumentNullException(nameof(destination));

            byte[] buffer = new byte[bufferSize];
            int bytesRead;
            while ((bytesRead = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                destination.Write(buffer, 0, bytesRead);
            }
        }

        /// <summary>
        /// 验证文件路径
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="mustExist">是否必须存在</param>
        /// <returns>是否有效</returns>
        public static bool ValidateFilePath(string filePath, bool mustExist = true)
        {
            if (string.IsNullOrWhiteSpace(filePath))
                return false;

            try
            {
                // 检查路径格式
                Path.GetFullPath(filePath);

                if (mustExist)
                {
                    return File.Exists(filePath);
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 异常处理

        /// <summary>
        /// 创建加密异常
        /// </summary>
        /// <param name="message">异常消息</param>
        /// <param name="innerException">内部异常</param>
        /// <returns>加密异常</returns>
        public static CryptographicException CreateCryptoException(string message, Exception innerException = null)
        {
            return new CryptographicException(message, innerException);
        }

        /// <summary>
        /// 创建参数异常
        /// </summary>
        /// <param name="paramName">参数名</param>
        /// <param name="message">异常消息</param>
        /// <returns>参数异常</returns>
        public static ArgumentException CreateArgumentException(string paramName, string message)
        {
            return new ArgumentException(message, paramName);
        }

        #endregion
    }
}
