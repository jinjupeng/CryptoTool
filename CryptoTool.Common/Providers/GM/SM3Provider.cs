using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.IO;
using System.Text;

namespace CryptoTool.Common.Providers.GM
{
    /// <summary>
    /// 国密SM3杂凑算法工具类
    /// SM3是中华人民共和国政府采用的一种密码散列函数标准，由国家密码管理局于2010年12月17日发布。
    /// 相关标准为"GM/T 0004-2012 《SM3密码杂凑算法》"。
    /// SM3适用于商用密码应用中的数字签名和验证，消息认证码生成与验证，随机数生成等，可满足多种密码应用的安全需求。
    /// </summary>
    public class SM3Provider : IHashProvider
    {
        #region 常量

        /// <summary>
        /// SM3摘要长度（字节)
        /// </summary>
        public const int DIGEST_LENGTH = 32;

        /// <summary>
        /// SM3摘要长度（位）
        /// </summary>
        public const int DIGEST_LENGTH_BITS = DIGEST_LENGTH * 8;

        #endregion

        #region IHashProvider 实现

        /// <summary>
        /// 算法类型
        /// </summary>
        public AlgorithmType AlgorithmType => AlgorithmType.SM3;

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
        public byte[] ComputeHash(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(data, 0, data.Length);

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return hash;
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
        /// 计算字符串哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHashWithFormat(string data, string outputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] hash = ComputeHash(dataBytes);

            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hash),
                _ => CryptoCommonUtil.ConvertToHexString(hash, true)
            };
        }

        /// <summary>
        /// 计算字符串哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        public string ComputeHashWithFormat(byte[] dataBytes, string outputFormat = "Hex")
        {
            byte[] hash = ComputeHash(dataBytes);

            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hash),
                _ => CryptoCommonUtil.ConvertToHexString(hash, true)
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

            using (var fileStream = File.OpenRead(filePath))
            {
                return ComputeStreamHashWithFormat(fileStream, outputFormat);
            }
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

            SM3Digest digest = new SM3Digest();
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(hash),
                _ => CryptoCommonUtil.ConvertToHexString(hash, true)
            };
        }

        /// <summary>
        /// 验证字符串哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHashWithFormat(string data, string expectedHash, string inputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(expectedHash))
                return false;

            string computedHash = ComputeHashWithFormat(data, inputFormat);
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

            string computedHash = ComputeHashWithFormat(data, inputFormat);
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 验证字节数组哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedBytes">期望的哈希值</param>
        /// <returns>是否匹配</returns>
        public bool VerifyHashWithFormat(byte[] data, byte[] expectedBytes)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("原始数据不能为空", nameof(data));
            if (expectedBytes == null || expectedBytes.Length == 0)
                throw new ArgumentException("期望的哈希值不能为空", nameof(expectedBytes));

            string computedHash = ComputeHashWithFormat(data, "Hex");
            string expectedHash = CryptoCommonUtil.ConvertToHexString(expectedBytes, true);
            return string.Equals(computedHash, expectedHash, StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region 高级功能

        /// <summary>
        /// 计算HMAC-SM3
        /// </summary>
        /// <param name="data">待计算数据(UTF-8)</param>
        /// <param name="key">密钥(UTF-8)</param>
        /// <param name="outputFormat">输出格式（默认是Hex）</param>
        /// <returns>HMAC值</returns>
        public string ComputeHMac(string data, string key, string outputFormat = "Hex")
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            byte[] dataBytes = Encoding.UTF8.GetBytes(data);
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            return ComputeHMac(dataBytes, keyBytes, outputFormat);
        }

        /// <summary>
        /// 计算HMAC-SM3
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="key">密钥</param>
        /// <param name="outputFormat">输出格式(默认是Hex)</param>
        /// <returns>HMAC值</returns>
        public string ComputeHMac(byte[] data, byte[] key, string outputFormat = "Hex")
        {
            byte[] result = ComputeHMac(data, key);

            return outputFormat?.ToLowerInvariant() switch
            {
                "base64" => Convert.ToBase64String(result),
                _ => CryptoCommonUtil.ConvertToHexString(result, true)
            };
        }

        /// <summary>
        /// 计算HMAC-SM3
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="key">密钥</param>
        /// <returns>HMAC值</returns>
        public byte[] ComputeHMac(byte[] data, byte[] key)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (key == null || key.Length == 0)
                throw new ArgumentException("密钥不能为空", nameof(key));

            // 使用BouncyCastle的HMAC实现
            var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new SM3Digest());
            var keyParam = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key);
            hmac.Init(keyParam);

            hmac.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);

            return result;
        }

        #endregion
    }
}