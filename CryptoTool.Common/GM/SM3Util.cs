using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Text;

namespace CryptoTool.Common.GM
{
    /// <summary>
    /// 国密SM3杂凑算法工具类
    /// SM3是中华人民共和国政府采用的一种密码散列函数标准，由国家密码管理局于2010年12月17日发布。
    /// 相关标准为"GM/T 0004-2012 《SM3密码杂凑算法》"。
    /// SM3适用于商用密码应用中的数字签名和验证，消息认证码生成与验证，随机数生成等，可满足多种密码应用的安全需求。
    /// </summary>
    public static class SM3Util
    {
        /// <summary>
        /// SM3摘要长度（字节)
        /// </summary>
        public const int DIGEST_LENGTH = 32;

        /// <summary>
        /// SM3摘要长度（位）
        /// </summary>
        public const int DIGEST_LENGTH_BITS = DIGEST_LENGTH * 8;

        /// <summary>
        /// 计算数据的SM3哈希值
        /// </summary>
        /// <param name="data">要计算哈希的数据</param>
        /// <returns>哈希值字节数组</returns>
        public static byte[] ComputeHash(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            SM3Digest digest = new SM3Digest();
            digest.BlockUpdate(data, 0, data.Length);
            
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            
            return hash;
        }

        /// <summary>
        /// 计算字符串的SM3哈希值
        /// </summary>
        /// <param name="data">要计算哈希的字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>哈希值字节数组</returns>
        public static byte[] ComputeHash(string data, Encoding encoding = null)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return ComputeHash(dataBytes);
        }

        /// <summary>
        /// 计算数据的SM3哈希值并返回16进制字符串
        /// </summary>
        /// <param name="data">要计算哈希的数据</param>
        /// <returns>哈希值的16进制字符串（大写）</returns>
        public static string ComputeHashHex(byte[] data)
        {
            byte[] hash = ComputeHash(data);
            return Hex.ToHexString(hash).ToUpper();
        }

        /// <summary>
        /// 计算字符串的SM3哈希值并返回16进制字符串
        /// </summary>
        /// <param name="data">要计算哈希的字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>哈希值的16进制字符串（大写）</returns>
        public static string ComputeHashHex(string data, Encoding encoding = null)
        {
            byte[] hash = ComputeHash(data, encoding);
            return Hex.ToHexString(hash).ToUpper();
        }

        /// <summary>
        /// 计算数据的SM3哈希值并返回Base64字符串
        /// </summary>
        /// <param name="data">要计算哈希的数据</param>
        /// <returns>哈希值的Base64字符串</returns>
        public static string ComputeHashBase64(byte[] data)
        {
            byte[] hash = ComputeHash(data);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// 计算字符串的SM3哈希值并返回Base64字符串
        /// </summary>
        /// <param name="data">要计算哈希的字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>哈希值的Base64字符串</returns>
        public static string ComputeHashBase64(string data, Encoding encoding = null)
        {
            byte[] hash = ComputeHash(data, encoding);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// 计算文件的SM3哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>哈希值字节数组</returns>
        public static byte[] ComputeFileHash(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));

            if (!File.Exists(filePath))
                throw new FileNotFoundException($"文件不存在: {filePath}");

            using (FileStream fileStream = File.OpenRead(filePath))
            {
                return ComputeStreamHash(fileStream);
            }
        }

        /// <summary>
        /// 计算文件的SM3哈希值并返回16进制字符串
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>哈希值的16进制字符串（大写）</returns>
        public static string ComputeFileHashHex(string filePath)
        {
            byte[] hash = ComputeFileHash(filePath);
            return Hex.ToHexString(hash).ToUpper();
        }

        /// <summary>
        /// 计算文件的SM3哈希值并返回Base64字符串
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>哈希值的Base64字符串</returns>
        public static string ComputeFileHashBase64(string filePath)
        {
            byte[] hash = ComputeFileHash(filePath);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// 计算流的SM3哈希值
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <returns>哈希值字节数组</returns>
        public static byte[] ComputeStreamHash(Stream stream)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));

            SM3Digest digest = new SM3Digest();
            byte[] buffer = new byte[8192]; // 8KB缓冲区
            int bytesRead;

            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }

            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return hash;
        }

        /// <summary>
        /// 计算流的SM3哈希值并返回16进制字符串
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <returns>哈希值的16进制字符串（大写）</returns>
        public static string ComputeStreamHashHex(Stream stream)
        {
            byte[] hash = ComputeStreamHash(stream);
            return Hex.ToHexString(hash).ToUpper();
        }

        /// <summary>
        /// 计算流的SM3哈希值并返回Base64字符串
        /// </summary>
        /// <param name="stream">输入流</param>
        /// <returns>哈希值的Base64字符串</returns>
        public static string ComputeStreamHashBase64(Stream stream)
        {
            byte[] hash = ComputeStreamHash(stream);
            return Convert.ToBase64String(hash);
        }

        /// <summary>
        /// HMAC-SM3计算
        /// </summary>
        /// <param name="data">要计算HMAC的数据</param>
        /// <param name="key">HMAC密钥</param>
        /// <returns>HMAC值字节数组</returns>
        public static byte[] ComputeHMac(byte[] data, byte[] key)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            var hmac = MacUtilities.GetMac("HMAC-SM3");
            hmac.Init(new KeyParameter(key));
            hmac.BlockUpdate(data, 0, data.Length);
            
            byte[] result = new byte[hmac.GetMacSize()];
            hmac.DoFinal(result, 0);
            
            return result;
        }

        /// <summary>
        /// HMAC-SM3计算
        /// </summary>
        /// <param name="data">要计算HMAC的字符串</param>
        /// <param name="key">HMAC密钥字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>HMAC值字节数组</returns>
        public static byte[] ComputeHMac(string data, string key, Encoding encoding = null)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            byte[] keyBytes = encoding.GetBytes(key);
            
            return ComputeHMac(dataBytes, keyBytes);
        }

        /// <summary>
        /// HMAC-SM3计算并返回16进制字符串
        /// </summary>
        /// <param name="data">要计算HMAC的数据</param>
        /// <param name="key">HMAC密钥</param>
        /// <returns>HMAC值的16进制字符串（大写）</returns>
        public static string ComputeHMacHex(byte[] data, byte[] key)
        {
            byte[] hmac = ComputeHMac(data, key);
            return Hex.ToHexString(hmac).ToUpper();
        }

        /// <summary>
        /// HMAC-SM3计算并返回16进制字符串
        /// </summary>
        /// <param name="data">要计算HMAC的字符串</param>
        /// <param name="key">HMAC密钥字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>HMAC值的16进制字符串（大写）</returns>
        public static string ComputeHMacHex(string data, string key, Encoding encoding = null)
        {
            byte[] hmac = ComputeHMac(data, key, encoding);
            return Hex.ToHexString(hmac).ToUpper();
        }

        /// <summary>
        /// HMAC-SM3计算并返回Base64字符串
        /// </summary>
        /// <param name="data">要计算HMAC的数据</param>
        /// <param name="key">HMAC密钥</param>
        /// <returns>HMAC值的Base64字符串</returns>
        public static string ComputeHMacBase64(byte[] data, byte[] key)
        {
            byte[] hmac = ComputeHMac(data, key);
            return Convert.ToBase64String(hmac);
        }

        /// <summary>
        /// HMAC-SM3计算并返回Base64字符串
        /// </summary>
        /// <param name="data">要计算HMAC的字符串</param>
        /// <param name="key">HMAC密钥字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>HMAC值的Base64字符串</returns>
        public static string ComputeHMacBase64(string data, string key, Encoding encoding = null)
        {
            byte[] hmac = ComputeHMac(data, key, encoding);
            return Convert.ToBase64String(hmac);
        }

        /// <summary>
        /// 验证数据的SM3哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <returns>验证结果</returns>
        public static bool VerifyHash(byte[] data, byte[] expectedHash)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (expectedHash == null)
                throw new ArgumentNullException(nameof(expectedHash));

            byte[] actualHash = ComputeHash(data);
            return Arrays.AreEqual(actualHash, expectedHash);
        }

        /// <summary>
        /// 验证数据的SM3哈希值（16进制字符串）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHashHex">期望的哈希值（16进制字符串）</param>
        /// <returns>验证结果</returns>
        public static bool VerifyHashHex(byte[] data, string expectedHashHex)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(expectedHashHex))
                throw new ArgumentNullException(nameof(expectedHashHex));

            string actualHashHex = ComputeHashHex(data);
            return string.Equals(actualHashHex, expectedHashHex, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 验证字符串的SM3哈希值
        /// </summary>
        /// <param name="data">原始字符串</param>
        /// <param name="expectedHashHex">期望的哈希值（16进制字符串）</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>验证结果</returns>
        public static bool VerifyHashHex(string data, string expectedHashHex, Encoding encoding = null)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (string.IsNullOrEmpty(expectedHashHex))
                throw new ArgumentNullException(nameof(expectedHashHex));

            string actualHashHex = ComputeHashHex(data, encoding);
            return string.Equals(actualHashHex, expectedHashHex, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 验证文件的SM3哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="expectedHashHex">期望的哈希值（16进制字符串）</param>
        /// <returns>验证结果</returns>
        public static bool VerifyFileHashHex(string filePath, string expectedHashHex)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentNullException(nameof(filePath));
            if (string.IsNullOrEmpty(expectedHashHex))
                throw new ArgumentNullException(nameof(expectedHashHex));

            string actualHashHex = ComputeFileHashHex(filePath);
            return string.Equals(actualHashHex, expectedHashHex, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// 创建SM3摘要器的实例（用于增量计算）
        /// </summary>
        /// <returns>SM3摘要器实例</returns>
        public static SM3Digest CreateDigest()
        {
            return new SM3Digest();
        }

        /// <summary>
        /// 将16进制字符串转换为字节数组
        /// </summary>
        /// <param name="hexString">16进制字符串</param>
        /// <returns>字节数组</returns>
        public static byte[] HexToBytes(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentNullException(nameof(hexString));

            return Hex.Decode(hexString);
        }

        /// <summary>
        /// 将字节数组转换为16进制字符串
        /// </summary>
        /// <param name="bytes">字节数组</param>
        /// <returns>16进制字符串（大写）</returns>
        public static string BytesToHex(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            return Hex.ToHexString(bytes).ToUpper();
        }
    }
}
