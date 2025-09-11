using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Common;

namespace CryptoTool.Common
{
    /// <summary>
    /// MD5加密和哈希计算工具类
    /// 提供字符串、文件、流的MD5哈希计算功能
    /// </summary>
    public class MD5Util : IHashProvider
    {
        #region IHashProvider 实现

        /// <summary>
        /// 算法类型
        /// </summary>
        public AlgorithmType AlgorithmType => AlgorithmType.MD5;

        /// <summary>
        /// 计算哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHash(string data, OutputFormat outputFormat = OutputFormat.Hex)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            return ComputeHash(dataBytes, outputFormat);
        }

        /// <summary>
        /// 计算字节数组哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHash(byte[] data, OutputFormat outputFormat = OutputFormat.Hex)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(data);
                return CryptoCommon.BytesToString(hashBytes, outputFormat);
            }
        }

        /// <summary>
        /// 计算文件哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeFileHash(string filePath, OutputFormat outputFormat = OutputFormat.Hex)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("文件路径不能为空", nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"文件不存在: {filePath}");

            using (var md5 = MD5.Create())
            using (var fileStream = File.OpenRead(filePath))
            {
                byte[] hashBytes = md5.ComputeHash(fileStream);
                return CryptoCommon.BytesToString(hashBytes, outputFormat);
            }
        }

        /// <summary>
        /// 计算流哈希值
        /// </summary>
        /// <param name="stream">流</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeStreamHash(Stream stream, OutputFormat outputFormat = OutputFormat.Hex)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            using (var md5 = MD5.Create())
            {
                byte[] hashBytes = md5.ComputeHash(stream);
                return CryptoCommon.BytesToString(hashBytes, outputFormat);
            }
        }

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHash(string data, string expectedHash, InputFormat inputFormat = InputFormat.Hex)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(expectedHash))
                return false;

            string computedHash = ComputeHash(data, OutputFormat.Hex);
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 验证字节数组哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHash(byte[] data, string expectedHash, InputFormat inputFormat = InputFormat.Hex)
        {
            if (data == null || data.Length == 0 || string.IsNullOrEmpty(expectedHash))
                return false;

            string computedHash = ComputeHash(data, OutputFormat.Hex);
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        #endregion
    }
}