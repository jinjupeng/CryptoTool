using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Interfaces;
using System;

namespace CryptoTool.Algorithm.Algorithms.MD5
{
    /// <summary>
    /// MD5哈希算法实现
    /// </summary>
    public class Md5Hash : IHashAlgorithm
    {
        public string AlgorithmName => "MD5";
        public CryptoAlgorithmType AlgorithmType => CryptoAlgorithmType.Hash;
        public int HashLength => 16; // MD5输出128位，即16字节

        /// <summary>
        /// 计算哈希值
        /// </summary>
        public byte[] ComputeHash(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待计算数据不能为空");

            try
            {
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    return md5.ComputeHash(data);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("MD5哈希计算失败", ex);
            }
        }

        /// <summary>
        /// 计算字符串的MD5哈希值
        /// </summary>
        /// <param name="text">待计算字符串</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>MD5哈希值</returns>
        public byte[] ComputeHash(string text, System.Text.Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(text))
                throw new DataException("待计算字符串不能为空");

            encoding ??= System.Text.Encoding.UTF8;
            var data = encoding.GetBytes(text);
            return ComputeHash(data);
        }

        /// <summary>
        /// 计算字符串的MD5哈希值（十六进制字符串）
        /// </summary>
        /// <param name="text">待计算字符串</param>
        /// <param name="upperCase">是否大写</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>MD5哈希值（十六进制字符串）</returns>
        public string ComputeHashString(string text, bool upperCase = false, System.Text.Encoding? encoding = null)
        {
            var hash = ComputeHash(text, encoding);
            return Utils.StringUtil.BytesToHex(hash, upperCase);
        }

        /// <summary>
        /// 计算字节数组的MD5哈希值（十六进制字符串）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>MD5哈希值（十六进制字符串）</returns>
        public string ComputeHashString(byte[] data, bool upperCase = false)
        {
            var hash = ComputeHash(data);
            return Utils.StringUtil.BytesToHex(hash, upperCase);
        }

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="hash">待验证的哈希值</param>
        /// <returns>验证结果</returns>
        public bool VerifyHash(byte[] data, byte[] hash)
        {
            if (data == null || data.Length == 0)
                throw new DataException("原始数据不能为空");

            if (hash == null || hash.Length == 0)
                throw new DataException("待验证哈希值不能为空");

            if (hash.Length != HashLength)
                throw new DataException($"哈希值长度必须为{HashLength}字节");

            var computedHash = ComputeHash(data);
            return Utils.StringUtil.SecureByteArraysEqual(computedHash, hash);
        }

        /// <summary>
        /// 验证哈希值（十六进制字符串）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="hashString">待验证的哈希值（十六进制字符串）</param>
        /// <returns>验证结果</returns>
        public bool VerifyHash(byte[] data, string hashString)
        {
            if (string.IsNullOrEmpty(hashString))
                throw new DataException("待验证哈希值不能为空");

            try
            {
                var hash = Utils.StringUtil.HexToBytes(hashString);
                return VerifyHash(data, hash);
            }
            catch (Exception ex)
            {
                throw new DataException("无效的十六进制哈希值", ex);
            }
        }

        /// <summary>
        /// 验证字符串哈希值
        /// </summary>
        /// <param name="text">原始字符串</param>
        /// <param name="hashString">待验证的哈希值（十六进制字符串）</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>验证结果</returns>
        public bool VerifyHash(string text, string hashString, System.Text.Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(text))
                throw new DataException("原始字符串不能为空");

            encoding ??= System.Text.Encoding.UTF8;
            var data = encoding.GetBytes(text);
            return VerifyHash(data, hashString);
        }

        /// <summary>
        /// 计算文件的MD5哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>MD5哈希值</returns>
        public byte[] ComputeFileHash(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("文件路径不能为空", nameof(filePath));

            if (!System.IO.File.Exists(filePath))
                throw new System.IO.FileNotFoundException($"文件不存在: {filePath}");

            try
            {
                using (var md5 = System.Security.Cryptography.MD5.Create())
                using (var stream = System.IO.File.OpenRead(filePath))
                {
                    return md5.ComputeHash(stream);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("文件MD5哈希计算失败", ex);
            }
        }

        /// <summary>
        /// 计算文件的MD5哈希值（十六进制字符串）
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>MD5哈希值（十六进制字符串）</returns>
        public string ComputeFileHashString(string filePath, bool upperCase = false)
        {
            var hash = ComputeFileHash(filePath);
            return Utils.StringUtil.BytesToHex(hash, upperCase);
        }
    }
}
