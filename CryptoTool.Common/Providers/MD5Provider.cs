using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common.Providers
{
    /// <summary>
    /// MD5加密和哈希计算工具类
    /// 提供字符串、文件、流的MD5哈希计算功能
    /// </summary>
    public class MD5Provider : IHashProvider
    {
        #region IHashProvider 实现

        /// <summary>
        /// 算法类型
        /// </summary>
        public AlgorithmType AlgorithmType => AlgorithmType.MD5;

        /// <summary>
        /// 计算字符串哈希值（接口实现）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值（十六进制）</returns>
        public string ComputeHash(string data)
        {
            return ComputeHashWithFormat(data, "Hex");
        }

        /// <summary>
        /// 计算字节数组哈希值（接口实现）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值（十六进制）</returns>
        public byte[] ComputeHash(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            using var md5 = MD5.Create();
            byte[] hashBytes = md5.ComputeHash(data);
            return hashBytes;
        }

        /// <summary>
        /// 计算文件哈希值（接口实现）
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>哈希值（十六进制）</returns>
        public string ComputeFileHash(string filePath)
        {
            return ComputeFileHashWithFormat(filePath, "Hex");
        }

        /// <summary>
        /// 计算流哈希值（接口实现）
        /// </summary>
        /// <param name="stream">流</param>
        /// <returns>哈希值（十六进制）</returns>
        public string ComputeStreamHash(Stream stream)
        {
            return ComputeStreamHashWithFormat(stream, "Hex");
        }

        /// <summary>
        /// 验证字符串哈希值（接口实现）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHash(string data, string expectedHash)
        {
            return VerifyHashWithFormat(data, expectedHash, "Hex");
        }

        /// <summary>
        /// 验证字节数组哈希值（接口实现）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHash(byte[] data, string expectedHash)
        {
            return VerifyHashWithFormat(data, expectedHash, "Hex");
        }

        #endregion

        #region 扩展方法

        /// <summary>
        /// 计算哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHashWithFormat(string data, string outputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return ComputeHashWithFormat(dataBytes, outputFormat);
        }

        /// <summary>
        /// 计算字节数组哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHashWithFormat(byte[] data, string outputFormat = "Hex")
        {
            byte[] hashBytes = ComputeHash(data);
            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hashBytes),
                _ => CryptoCommonUtil.ConvertToHexString(hashBytes, true)
            };
        }

        /// <summary>
        /// 计算文件哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeFileHashWithFormat(string filePath, string outputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("文件路径不能为空", nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"文件不存在: {filePath}");

            using var md5 = MD5.Create();
            using var fileStream = File.OpenRead(filePath);
            byte[] hashBytes = md5.ComputeHash(fileStream);
            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hashBytes),
                _ => CryptoCommonUtil.ConvertToHexString(hashBytes, true)
            };
        }

        /// <summary>
        /// 计算流哈希值
        /// </summary>
        /// <param name="stream">流</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeStreamHashWithFormat(Stream stream, string outputFormat = "Hex")
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using var md5 = MD5.Create();
            byte[] hashBytes = md5.ComputeHash(stream);
            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hashBytes),
                _ => CryptoCommonUtil.ConvertToHexString(hashBytes, true)
            };
        }

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHashWithFormat(string data, string expectedHash, string inputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(expectedHash))
                return false;

            string computedHash = ComputeHashWithFormat(data, "Hex");
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 验证字节数组哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHashWithFormat(byte[] data, string expectedHash, string inputFormat = "Hex")
        {
            if (data == null || data.Length == 0 || string.IsNullOrEmpty(expectedHash))
                return false;

            string computedHash = ComputeHashWithFormat(data, "Hex");
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        #endregion
    }
}