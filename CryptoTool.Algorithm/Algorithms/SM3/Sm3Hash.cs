using CryptoTool.Algorithm.Interfaces;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoTool.Algorithm.Algorithms.SM3
{
    /// <summary>
    /// SM3国密哈希算法实现
    /// 基于BouncyCastle库的生产级实现
    /// </summary>
    public class Sm3Hash : IHashAlgorithm
    {
        public string AlgorithmName => "SM3";
        public CryptoAlgorithmType AlgorithmType => CryptoAlgorithmType.Hash;

        /// <summary>
        /// SM3输出256位，即32字节
        /// </summary>
        public int HashLength => 32;

        /// <summary>
        /// 计算哈希值
        /// </summary>
        public byte[] ComputeHash(byte[] data)
        {
            if (data == null)
                throw new Exceptions.DataException("待计算数据不能为null");

            try
            {
                var digest = new SM3Digest();
                var result = new byte[digest.GetDigestSize()];

                if (data.Length > 0)
                {
                    digest.BlockUpdate(data, 0, data.Length);
                }

                digest.DoFinal(result, 0);
                return result;
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("SM3哈希计算失败", ex);
            }
        }

        /// <summary>
        /// 计算字符串的SM3哈希值
        /// </summary>
        /// <param name="text">待计算字符串</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>SM3哈希值</returns>
        public byte[] ComputeHash(string text, System.Text.Encoding? encoding = null)
        {
            if (string.IsNullOrEmpty(text))
                throw new Exceptions.DataException("待计算字符串不能为空");

            encoding ??= System.Text.Encoding.UTF8;
            var data = encoding.GetBytes(text);
            return ComputeHash(data);
        }

        /// <summary>
        /// 计算字符串的SM3哈希值（十六进制字符串）
        /// </summary>
        /// <param name="text">待计算字符串</param>
        /// <param name="upperCase">是否大写</param>
        /// <param name="encoding">编码方式，默认UTF-8</param>
        /// <returns>SM3哈希值（十六进制字符串）</returns>
        public string ComputeHashString(string text, bool upperCase = false, System.Text.Encoding? encoding = null)
        {
            var hash = ComputeHash(text, encoding);
            return Utils.StringUtil.BytesToHex(hash, upperCase);
        }

        /// <summary>
        /// 计算字节数组的SM3哈希值（十六进制字符串）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>SM3哈希值（十六进制字符串）</returns>
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
                throw new Exceptions.DataException("原始数据不能为空");

            if (hash == null || hash.Length == 0)
                throw new Exceptions.DataException("待验证哈希值不能为空");

            if (hash.Length != HashLength)
                throw new Exceptions.DataException($"哈希值长度必须为{HashLength}字节");

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
                throw new Exceptions.DataException("待验证哈希值不能为空");

            try
            {
                var hash = Utils.StringUtil.HexToBytes(hashString);
                return VerifyHash(data, hash);
            }
            catch (Exception ex)
            {
                throw new Exceptions.DataException("无效的十六进制哈希值", ex);
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
                throw new Exceptions.DataException("原始字符串不能为空");

            encoding ??= System.Text.Encoding.UTF8;
            var data = encoding.GetBytes(text);
            return VerifyHash(data, hashString);
        }

        /// <summary>
        /// 计算文件的SM3哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>SM3哈希值</returns>
        public byte[] ComputeFileHash(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("文件路径不能为空", nameof(filePath));

            if (!System.IO.File.Exists(filePath))
                throw new System.IO.FileNotFoundException($"文件不存在: {filePath}");

            try
            {
                var digest = new SM3Digest();
                var result = new byte[digest.GetDigestSize()];

                using (var stream = System.IO.File.OpenRead(filePath))
                {
                    var buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        digest.BlockUpdate(buffer, 0, bytesRead);
                    }
                }

                digest.DoFinal(result, 0);
                return result;
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("文件SM3哈希计算失败", ex);
            }
        }

        /// <summary>
        /// 计算文件的SM3哈希值（十六进制字符串）
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>SM3哈希值（十六进制字符串）</returns>
        public string ComputeFileHashString(string filePath, bool upperCase = false)
        {
            var hash = ComputeFileHash(filePath);
            return Utils.StringUtil.BytesToHex(hash, upperCase);
        }

        /// <summary>
        /// 计算HMAC-SM3
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="key">密钥</param>
        /// <returns>HMAC-SM3值</returns>
        public byte[] ComputeHmac(byte[] data, byte[] key)
        {
            if (data == null || data.Length == 0)
                throw new Exceptions.DataException("待计算数据不能为空");

            if (key == null || key.Length == 0)
                throw new Exceptions.KeyException("密钥不能为空");

            try
            {
                var hmac = new Org.BouncyCastle.Crypto.Macs.HMac(new SM3Digest());
                var keyParam = new Org.BouncyCastle.Crypto.Parameters.KeyParameter(key);
                hmac.Init(keyParam);

                var result = new byte[hmac.GetMacSize()];
                hmac.BlockUpdate(data, 0, data.Length);
                hmac.DoFinal(result, 0);
                return result;
            }
            catch (Exception ex)
            {
                throw new Exceptions.CryptoException("HMAC-SM3计算失败", ex);
            }
        }

        /// <summary>
        /// 计算HMAC-SM3（十六进制字符串）
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="key">密钥</param>
        /// <param name="upperCase">是否大写</param>
        /// <returns>HMAC-SM3值（十六进制字符串）</returns>
        public string ComputeHmacString(byte[] data, byte[] key, bool upperCase = false)
        {
            var hmac = ComputeHmac(data, key);
            return Utils.StringUtil.BytesToHex(hmac, upperCase);
        }
    }
}