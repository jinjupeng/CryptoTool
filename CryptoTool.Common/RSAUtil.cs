using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoTool.Common
{
    /// <summary>
    /// RSA工具类，支持RSA、RSA2算法，支持PKCS1和PKCS8格式转换
    /// </summary>
    public class RSAUtil
    {
        #region 枚举定义

        /// <summary>
        /// RSA算法类型
        /// </summary>
        public enum RSAType
        {
            /// <summary>
            /// RSA算法，使用SHA1哈希
            /// </summary>
            RSA = 1,
            /// <summary>
            /// RSA2算法，使用SHA256哈希
            /// </summary>
            RSA2 = 2
        }

        /// <summary>
        /// 密钥格式
        /// </summary>
        public enum RSAKeyFormat
        {
            /// <summary>
            /// XML格式（C#默认格式）
            /// </summary>
            XML,
            /// <summary>
            /// PKCS1格式（非JAVA适用）
            /// </summary>
            PKCS1,
            /// <summary>
            /// PKCS8格式（JAVA适用）
            /// </summary>
            PKCS8
        }

        /// <summary>
        /// 填充模式
        /// </summary>
        public enum RSAPaddingMode
        {
            /// <summary>
            /// PKCS#1 v1.5填充
            /// </summary>
            PKCS1,
            /// <summary>
            /// OAEP填充
            /// </summary>
            OAEP,
            /// <summary>
            /// 无填充（仅用于特殊场景）
            /// </summary>
            NoPadding
        }

        /// <summary>
        /// 输出格式
        /// </summary>
        public enum RSAOutputFormat
        {
            /// <summary>
            /// 字符串格式
            /// </summary>
            String,
            /// <summary>
            /// Base64格式
            /// </summary>
            Base64,
            /// <summary>
            /// 十六进制格式
            /// </summary>
            Hex,
            /// <summary>
            /// PEM格式
            /// </summary>
            Pem
        }

        /// <summary>
        /// 字符集编码
        /// </summary>
        public enum RSAEncoding
        {
            /// <summary>
            /// UTF-8编码
            /// </summary>
            UTF8,
            /// <summary>
            /// GBK编码
            /// </summary>
            GBK
        }

        /// <summary>
        /// 输入格式
        /// </summary>
        public enum RSAInputFormat
        {
            /// <summary>
            /// 字符串格式
            /// </summary>
            String,
            /// <summary>
            /// 十六进制格式
            /// </summary>
            Hex,
            /// <summary>
            /// Base64格式
            /// </summary>
            Base64
        }

        /// <summary>
        /// 签名算法
        /// </summary>
        public enum RSASignatureAlgorithm
        {
            /// <summary>
            /// SHA1
            /// </summary>
            SHA1,
            /// <summary>
            /// SHA256
            /// </summary>
            SHA256,
            /// <summary>
            /// SHA384
            /// </summary>
            SHA384,
            /// <summary>
            /// SHA512
            /// </summary>
            SHA512,
            /// <summary>
            /// MD5
            /// </summary>
            MD5
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 获取编码器
        /// </summary>
        private static Encoding GetEncoding(RSAEncoding encoding)
        {
            return encoding switch
            {
                RSAEncoding.UTF8 => Encoding.UTF8,
                RSAEncoding.GBK => Encoding.GetEncoding("GBK"),
                _ => Encoding.UTF8
            };
        }

        /// <summary>
        /// 获取哈希算法名称
        /// </summary>
        private static HashAlgorithmName GetHashAlgorithmName(RSASignatureAlgorithm algorithm)
        {
            return algorithm switch
            {
                RSASignatureAlgorithm.SHA1 => HashAlgorithmName.SHA1,
                RSASignatureAlgorithm.SHA256 => HashAlgorithmName.SHA256,
                RSASignatureAlgorithm.SHA384 => HashAlgorithmName.SHA384,
                RSASignatureAlgorithm.SHA512 => HashAlgorithmName.SHA512,
                RSASignatureAlgorithm.MD5 => HashAlgorithmName.MD5,
                _ => HashAlgorithmName.SHA256
            };
        }

        /// <summary>
        /// 获取RSA填充模式
        /// </summary>
        private static RSAEncryptionPadding GetRSAEncryptionPadding(RSAPaddingMode padding)
        {
            return padding switch
            {
                RSAPaddingMode.PKCS1 => RSAEncryptionPadding.Pkcs1,
                RSAPaddingMode.OAEP => RSAEncryptionPadding.OaepSHA256,
                RSAPaddingMode.NoPadding => throw new NotSupportedException("NoPadding模式需要特殊处理，请使用专门的方法"),
                _ => RSAEncryptionPadding.Pkcs1
            };
        }

        /// <summary>
        /// 将输入数据转换为字节数组
        /// </summary>
        private static byte[] ConvertInputToBytes(string input, RSAInputFormat inputFormat, RSAEncoding encoding)
        {
            var textEncoding = GetEncoding(encoding);
            
            return inputFormat switch
            {
                RSAInputFormat.String => textEncoding.GetBytes(input),
                RSAInputFormat.Hex => ConvertHexStringToBytes(input),
                RSAInputFormat.Base64 => Convert.FromBase64String(input),
                _ => textEncoding.GetBytes(input)
            };
        }

        /// <summary>
        /// 将字节数组转换为输出格式
        /// </summary>
        private static string ConvertBytesToOutput(byte[] data, RSAOutputFormat outputFormat)
        {
            return outputFormat switch
            {
                RSAOutputFormat.String => Encoding.UTF8.GetString(data),
                RSAOutputFormat.Base64 => Convert.ToBase64String(data),
                RSAOutputFormat.Hex => ConvertBytesToHexString(data),
                RSAOutputFormat.Pem => throw new NotSupportedException("PEM格式需要特殊处理，请使用专门的方法"),
                _ => Convert.ToBase64String(data)
            };
        }

        /// <summary>
        /// 将十六进制字符串转换为字节数组
        /// </summary>
        private static byte[] ConvertHexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex))
                return new byte[0];

            // 移除可能的空格和连字符
            hex = hex.Replace(" ", "").Replace("-", "");

            if (hex.Length % 2 != 0)
                throw new ArgumentException("十六进制字符串长度必须是偶数", nameof(hex));

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// 将字节数组转换为十六进制字符串
        /// </summary>
        private static string ConvertBytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToUpperInvariant();
        }

        /// <summary>
        /// 检测密钥格式
        /// </summary>
        private static RSAKeyFormat DetectKeyFormat(string key)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            key = key.Trim();

            if (key.StartsWith("<RSAKeyValue>"))
                return RSAKeyFormat.XML;
            if (key.StartsWith("-----BEGIN") && key.Contains("PRIVATE KEY"))
                return RSAKeyFormat.PKCS8;
            if (key.StartsWith("-----BEGIN") && key.Contains("PUBLIC KEY"))
                return RSAKeyFormat.PKCS8;
            if (key.StartsWith("-----BEGIN") && key.Contains("RSA PRIVATE KEY"))
                return RSAKeyFormat.PKCS1;
            if (key.StartsWith("-----BEGIN") && key.Contains("RSA PUBLIC KEY"))
                return RSAKeyFormat.PKCS1;
            if (IsBase64String(key))
                return RSAKeyFormat.PKCS8; // 将Base64字符串识别为PKCS8格式
            
            throw new ArgumentException("无法识别的密钥格式", nameof(key));
        }

        /// <summary>
        /// 检测是否为Base64字符串
        /// </summary>
        private static bool IsBase64String(string s)
        {
            if (string.IsNullOrEmpty(s))
                return false;

            try
            {
                Convert.FromBase64String(s);
                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region 基础RSA加密解密

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>密文字符串（Base64编码）</returns>
        public static string EncryptByRSA(string plaintext, string publicKey, RSAKeyFormat keyFormat = RSAKeyFormat.XML, RSAPaddingMode padding = RSAPaddingMode.PKCS1)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空", nameof(plaintext));
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plaintext);
            byte[] encryptedData = EncryptByRSA(dataToEncrypt, publicKey, keyFormat, padding);
            return Convert.ToBase64String(encryptedData);
        }

        /// <summary>
        /// RSA加密（增强版）
        /// </summary>
        /// <param name="input">输入数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>加密结果</returns>
        public static string EncryptByRSA(string input, string publicKey, RSAKeyFormat keyFormat, RSAPaddingMode padding, 
            RSAInputFormat inputFormat, RSAOutputFormat outputFormat, RSAEncoding encoding = RSAEncoding.UTF8)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("输入数据不能为空", nameof(input));
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            byte[] dataToEncrypt = ConvertInputToBytes(input, inputFormat, encoding);
            byte[] encryptedData = EncryptByRSA(dataToEncrypt, publicKey, keyFormat, padding);
            return ConvertBytesToOutput(encryptedData, outputFormat);
        }

        /// <summary>
        /// RSA加密（字节数组）
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>加密后的字节数组</returns>
        public static byte[] EncryptByRSA(byte[] data, string publicKey, RSAKeyFormat keyFormat = RSAKeyFormat.XML, RSAPaddingMode padding = RSAPaddingMode.PKCS1)
        {
            using var rsa = RSA.Create();
            ImportPublicKey(rsa, publicKey, keyFormat);

            var rsaPadding = GetRSAEncryptionPadding(padding);
            
            return rsa.Encrypt(data, rsaPadding);
        }

        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="ciphertext">密文（Base64编码）</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>明文字符串</returns>
        public static string DecryptByRSA(string ciphertext, string privateKey, RSAKeyFormat keyFormat = RSAKeyFormat.XML, RSAPaddingMode padding = RSAPaddingMode.PKCS1)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("密文不能为空", nameof(ciphertext));
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            byte[] encryptedData = Convert.FromBase64String(ciphertext);
            byte[] decryptedData = DecryptByRSA(encryptedData, privateKey, keyFormat, padding);
            return Encoding.UTF8.GetString(decryptedData);
        }

        /// <summary>
        /// RSA解密（增强版）
        /// </summary>
        /// <param name="input">输入密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>解密结果</returns>
        public static string DecryptByRSA(string input, string privateKey, RSAKeyFormat keyFormat, RSAPaddingMode padding,
            RSAInputFormat inputFormat, RSAOutputFormat outputFormat, RSAEncoding encoding = RSAEncoding.UTF8)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("输入数据不能为空", nameof(input));
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            byte[] encryptedData = ConvertInputToBytes(input, inputFormat, encoding);
            byte[] decryptedData = DecryptByRSA(encryptedData, privateKey, keyFormat, padding);
            return ConvertBytesToOutput(decryptedData, outputFormat);
        }

        /// <summary>
        /// RSA解密（字节数组）
        /// </summary>
        /// <param name="encryptedData">加密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="padding">填充模式</param>
        /// <returns>解密后的字节数组</returns>
        public static byte[] DecryptByRSA(byte[] encryptedData, string privateKey, RSAKeyFormat keyFormat = RSAKeyFormat.XML, RSAPaddingMode padding = RSAPaddingMode.PKCS1)
        {
            using var rsa = RSA.Create();
            ImportPrivateKey(rsa, privateKey, keyFormat);

            var rsaPadding = GetRSAEncryptionPadding(padding);
            
            return rsa.Decrypt(encryptedData, rsaPadding);
        }

        #endregion

        #region RSA/RSA2数字签名

        /// <summary>
        /// RSA/RSA2数字签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="rsaType">RSA算法类型</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>签名（Base64编码）</returns>
        public static string HashAndSignString(string plaintext, string privateKey, RSAType rsaType = RSAType.RSA, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("待签名文本不能为空", nameof(plaintext));
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            byte[] dataToSign = Encoding.UTF8.GetBytes(plaintext);
            byte[] signature = HashAndSignData(dataToSign, privateKey, rsaType, keyFormat);
            return Convert.ToBase64String(signature);
        }

        /// <summary>
        /// RSA数字签名（增强版）
        /// </summary>
        /// <param name="input">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>签名结果</returns>
        public static string HashAndSignString(string input, string privateKey, RSASignatureAlgorithm algorithm, RSAKeyFormat keyFormat,
            RSAInputFormat inputFormat, RSAOutputFormat outputFormat, RSAEncoding encoding = RSAEncoding.UTF8)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("待签名数据不能为空", nameof(input));
            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            byte[] dataToSign = ConvertInputToBytes(input, inputFormat, encoding);
            byte[] signature = HashAndSignData(dataToSign, privateKey, algorithm, keyFormat);
            return ConvertBytesToOutput(signature, outputFormat);
        }

        /// <summary>
        /// RSA/RSA2数字签名（字节数组）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="rsaType">RSA算法类型</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>签名字节数组</returns>
        public static byte[] HashAndSignData(byte[] data, string privateKey, RSAType rsaType = RSAType.RSA, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            using var rsa = RSA.Create();
            ImportPrivateKey(rsa, privateKey, keyFormat);

            var hashAlgorithm = rsaType == RSAType.RSA2 ? 
                HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            
            return rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// RSA数字签名（字节数组，增强版）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>签名字节数组</returns>
        public static byte[] HashAndSignData(byte[] data, string privateKey, RSASignatureAlgorithm algorithm, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            using var rsa = RSA.Create();
            ImportPrivateKey(rsa, privateKey, keyFormat);
            
            var hashAlgorithm = GetHashAlgorithmName(algorithm);
            return rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// 验证RSA/RSA2签名
        /// </summary>
        /// <param name="plaintext">原文</param>
        /// <param name="signedData">签名（Base64编码）</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="rsaType">RSA算法类型</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>验证结果</returns>
        public static bool VerifySigned(string plaintext, string signedData, string publicKey, RSAType rsaType = RSAType.RSA, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("原文不能为空", nameof(plaintext));
            if (string.IsNullOrEmpty(signedData))
                throw new ArgumentException("签名不能为空", nameof(signedData));
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            byte[] dataToVerify = Encoding.UTF8.GetBytes(plaintext);
            byte[] signatureBytes = Convert.FromBase64String(signedData);
            return VerifySignedData(dataToVerify, signatureBytes, publicKey, rsaType, keyFormat);
        }

        /// <summary>
        /// 验证RSA签名（增强版）
        /// </summary>
        /// <param name="input">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="signatureFormat">签名格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>验证结果</returns>
        public static bool VerifySigned(string input, string signature, string publicKey, RSASignatureAlgorithm algorithm, RSAKeyFormat keyFormat,
            RSAInputFormat inputFormat, RSAInputFormat signatureFormat, RSAEncoding encoding = RSAEncoding.UTF8)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("原始数据不能为空", nameof(input));
            if (string.IsNullOrEmpty(signature))
                throw new ArgumentException("签名不能为空", nameof(signature));
            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            byte[] dataToVerify = ConvertInputToBytes(input, inputFormat, encoding);
            byte[] signatureBytes = ConvertInputToBytes(signature, signatureFormat, encoding);
            return VerifySignedData(dataToVerify, signatureBytes, publicKey, algorithm, keyFormat);
        }

        /// <summary>
        /// 验证RSA/RSA2签名（字节数组）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签字数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="rsaType">RSA算法类型</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>验证结果</returns>
        public static bool VerifySignedData(byte[] data, byte[] signature, string publicKey, RSAType rsaType = RSAType.RSA, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            using var rsa = RSA.Create();
            ImportPublicKey(rsa, publicKey, keyFormat);
            
            var hashAlgorithm = rsaType == RSAType.RSA2 ? 
                HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
            
            return rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// 验证RSA签名（字节数组，增强版）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>验证结果</returns>
        public static bool VerifySignedData(byte[] data, byte[] signature, string publicKey, RSASignatureAlgorithm algorithm, RSAKeyFormat keyFormat = RSAKeyFormat.XML)
        {
            using var rsa = RSA.Create();
            ImportPublicKey(rsa, publicKey, keyFormat);
            
            var hashAlgorithm = GetHashAlgorithmName(algorithm);
            return rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        #endregion

        #region 密钥生成和格式转换

        /// <summary>
        /// 创建RSA密钥对
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="format">返回的密钥格式</param>
        /// <returns>密钥对（Key为公钥，Value为私钥）</returns>
        public static KeyValuePair<string, string> CreateRSAKey(int keySize = 2048, RSAKeyFormat format = RSAKeyFormat.XML)
        {
            using var rsa = RSA.Create(keySize);
            string publicKey = ExportPublicKey(rsa, format);
            string privateKey = ExportPrivateKey(rsa, format);
            return new KeyValuePair<string, string>(publicKey, privateKey);
        }

        /// <summary>
        /// 创建RSA密钥对（增强版）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密钥对（Key为公钥，Value为私钥）</returns>
        public static KeyValuePair<string, string> CreateRSAKey(int keySize, RSAKeyFormat keyFormat, RSAOutputFormat outputFormat)
        {
            using var rsa = RSA.Create(keySize);
            string publicKey = ExportPublicKey(rsa, keyFormat, outputFormat);
            string privateKey = ExportPrivateKey(rsa, keyFormat, outputFormat);
            return new KeyValuePair<string, string>(publicKey, privateKey);
        }

        /// <summary>
        /// 生成RSA密钥（支持多种输出格式）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <returns>密钥字符串</returns>
        public static string GenerateRSAKey(int keySize, RSAKeyFormat keyFormat, RSAOutputFormat outputFormat, bool isPrivateKey)
        {
            using var rsa = RSA.Create(keySize);
            return isPrivateKey ? 
                ExportPrivateKey(rsa, keyFormat, outputFormat) : 
                ExportPublicKey(rsa, keyFormat, outputFormat);
        }

        /// <summary>
        /// 导出公钥
        /// </summary>
        private static string ExportPublicKey(RSA rsa, RSAKeyFormat format) => format switch
        {
            RSAKeyFormat.XML => rsa.ToXmlString(false),
            RSAKeyFormat.PKCS1 => RSAKeyToPem(rsa.ToXmlString(false), isPrivateKey: false),
            RSAKeyFormat.PKCS8 => FormatPem(Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()), "PUBLIC KEY"),
            _ => throw new ArgumentException("不支持的密钥格式", nameof(format)),
        };

        /// <summary>
        /// 导出公钥（增强版）
        /// </summary>
        private static string ExportPublicKey(RSA rsa, RSAKeyFormat keyFormat, RSAOutputFormat outputFormat)
        {
            byte[] keyBytes = keyFormat switch
            {
                RSAKeyFormat.XML => throw new NotSupportedException("XML格式不支持输出格式转换"),
                RSAKeyFormat.PKCS1 => GetPkcs1PublicKeyBytes(rsa),
                RSAKeyFormat.PKCS8 => rsa.ExportSubjectPublicKeyInfo(),
                _ => throw new ArgumentException("不支持的密钥格式", nameof(keyFormat)),
            };

            return outputFormat switch
            {
                RSAOutputFormat.Base64 => Convert.ToBase64String(keyBytes),
                RSAOutputFormat.Hex => ConvertBytesToHexString(keyBytes),
                RSAOutputFormat.Pem => FormatPem(Convert.ToBase64String(keyBytes), "PUBLIC KEY"),
                _ => Convert.ToBase64String(keyBytes)
            };
        }

        /// <summary>
        /// 导出私钥
        /// </summary>
        private static string ExportPrivateKey(RSA rsa, RSAKeyFormat format)
        {
            switch (format)
            {
                case RSAKeyFormat.XML:
                    return rsa.ToXmlString(true);
                case RSAKeyFormat.PKCS1:
                    return RSAKeyToPem(rsa.ToXmlString(true), isPrivateKey: true);
                case RSAKeyFormat.PKCS8:
                    // .NET Standard 2.1兼容的PKCS8导出
                    byte[] pkcs8Bytes = ExportPkcs8PrivateKeyBytes(rsa);
                    return FormatPem(Convert.ToBase64String(pkcs8Bytes), "PRIVATE KEY");
                default:
                    throw new ArgumentException("不支持的密钥格式", nameof(format));
            }
        }

        /// <summary>
        /// 导出私钥（增强版）
        /// </summary>
        private static string ExportPrivateKey(RSA rsa, RSAKeyFormat keyFormat, RSAOutputFormat outputFormat)
        {
            byte[] keyBytes = keyFormat switch
            {
                RSAKeyFormat.XML => throw new NotSupportedException("XML格式不支持输出格式转换"),
                RSAKeyFormat.PKCS1 => GetPkcs1PrivateKeyBytes(rsa),
                RSAKeyFormat.PKCS8 => ExportPkcs8PrivateKeyBytes(rsa),
                _ => throw new ArgumentException("不支持的密钥格式", nameof(keyFormat)),
            };

            return outputFormat switch
            {
                RSAOutputFormat.Base64 => Convert.ToBase64String(keyBytes),
                RSAOutputFormat.Hex => ConvertBytesToHexString(keyBytes),
                RSAOutputFormat.Pem => FormatPem(Convert.ToBase64String(keyBytes), "PRIVATE KEY"),
                _ => Convert.ToBase64String(keyBytes)
            };
        }

        /// <summary>
        /// 使用.NET Standard 2.1兼容方法导出PKCS8私钥字节数组
        /// </summary>
        private static byte[] ExportPkcs8PrivateKeyBytes(RSA rsa)
        {
            try
            {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                // 对于.NET Core 3.0+和.NET 5+，使用原生方法
                return rsa.ExportPkcs8PrivateKey();
#else
                // 对于.NET Standard 2.1和早期版本，使用BouncyCastle实现
                return ExportPkcs8PrivateKeyBytesUsingBouncyCastle(rsa);
#endif
            }
            catch (Exception ex)
            {
                throw new CryptographicException("导出PKCS8私钥失败", ex);
            }
        }

        /// <summary>
        /// 使用BouncyCastle导出PKCS8私钥，兼容.NET Standard 2.1
        /// </summary>
        private static byte[] ExportPkcs8PrivateKeyBytesUsingBouncyCastle(RSA rsa)
        {
            try
            {
                RSAParameters rsaPara = rsa.ExportParameters(true);

                var key = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                    new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                    new BigInteger(1, rsaPara.InverseQ));

                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key);
                return privateKeyInfo.GetDerEncoded();
            }
            catch (Exception ex)
            {
                throw new CryptographicException("使用BouncyCastle导出PKCS8私钥失败", ex);
            }
        }

        /// <summary>
        /// 获取PKCS1公钥字节数组
        /// </summary>
        private static byte[] GetPkcs1PublicKeyBytes(RSA rsa)
        {
            try
            {
                RSAParameters rsaPara = rsa.ExportParameters(false);
                var key = new RsaKeyParameters(false, new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent));
                using var stream = new MemoryStream();
                using var writer = new StreamWriter(stream);
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
                writer.Flush();
                return stream.ToArray();
            }
            catch (Exception ex)
            {
                throw new CryptographicException("导出PKCS1公钥失败", ex);
            }
        }

        /// <summary>
        /// 获取PKCS1私钥字节数组
        /// </summary>
        private static byte[] GetPkcs1PrivateKeyBytes(RSA rsa)
        {
            try
            {
                RSAParameters rsaPara = rsa.ExportParameters(true);
                var key = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                    new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                    new BigInteger(1, rsaPara.InverseQ));
                using var stream = new MemoryStream();
                using var writer = new StreamWriter(stream);
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
                writer.Flush();
                return stream.ToArray();
            }
            catch (Exception ex)
            {
                throw new CryptographicException("导出PKCS1私钥失败", ex);
            }
        }

        /// <summary>
        /// 导入公钥
        /// </summary>
        private static void ImportPublicKey(RSA rsa, string publicKey, RSAKeyFormat format)
        {
            switch (format)
            {
                case RSAKeyFormat.XML:
                    rsa.FromXmlString(publicKey);
                    break;
                case RSAKeyFormat.PKCS1:
                    rsa.FromXmlString(PemToRSAKey(publicKey, isPrivateKey: false));
                    break;
                case RSAKeyFormat.PKCS8:
                    ImportSubjectPublicKeyInfo(rsa, publicKey);
                    break;
                default:
                    throw new ArgumentException("不支持的密钥格式", nameof(format));
            }
        }

        /// <summary>
        /// 导入私钥
        /// </summary>
        private static void ImportPrivateKey(RSA rsa, string privateKey, RSAKeyFormat format)
        {
            switch (format)
            {
                case RSAKeyFormat.XML:
                    rsa.FromXmlString(privateKey);
                    break;
                case RSAKeyFormat.PKCS1:
                    rsa.FromXmlString(PemToRSAKey(privateKey, isPrivateKey: true));
                    break;
                case RSAKeyFormat.PKCS8:
                    ImportPkcs8PrivateKey(rsa, privateKey);
                    break;
                default:
                    throw new ArgumentException("不支持的密钥格式", nameof(format));
            }
        }

        /// <summary>
        /// 导入PKCS8私钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportPkcs8PrivateKey(RSA rsa, string privateKey)
        {
            byte[] keyBytes = ExtractKeyBytesFromPem(privateKey);
            ImportPkcs8PrivateKeyFromBytes(rsa, keyBytes);
        }

        /// <summary>
        /// 从字节数组导入PKCS8私钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportPkcs8PrivateKeyFromBytes(RSA rsa, byte[] keyBytes)
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            // 对于.NET Core 3.0+和.NET 5+，使用原生方法
            rsa.ImportPkcs8PrivateKey(keyBytes, out _);
#else
            // 对于.NET Standard 2.1和早期版本，使用BouncyCastle实现
            ImportPkcs8PrivateKeyUsingBouncyCastle(rsa, keyBytes);
#endif
        }

        /// <summary>
        /// 导入SubjectPublicKeyInfo公钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportSubjectPublicKeyInfo(RSA rsa, string publicKey)
        {
            byte[] keyBytes = ExtractKeyBytesFromPem(publicKey);
            ImportSubjectPublicKeyInfoFromBytes(rsa, keyBytes);
        }

        /// <summary>
        /// 从字节数组导入SubjectPublicKeyInfo公钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportSubjectPublicKeyInfoFromBytes(RSA rsa, byte[] keyBytes)
        {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            // 对于.NET Core 3.0+和.NET 5+，使用原生方法
            rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
#else
            // 对于.NET Standard 2.1和早期版本，使用BouncyCastle实现
            ImportSubjectPublicKeyInfoUsingBouncyCastle(rsa, keyBytes);
#endif
        }

        /// <summary>
        /// 使用BouncyCastle导入PKCS8私钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportPkcs8PrivateKeyUsingBouncyCastle(RSA rsa, byte[] keyBytes)
        {
            try
            {
                var privateKeyInfo = PrivateKeyInfo.GetInstance(keyBytes);
                var rsaPrivateKey = RsaPrivateKeyStructure.GetInstance(privateKeyInfo.ParsePrivateKey());

                var rsaParams = new RSAParameters
                {
                    Modulus = rsaPrivateKey.Modulus.ToByteArrayUnsigned(),
                    Exponent = rsaPrivateKey.PublicExponent.ToByteArrayUnsigned(),
                    D = rsaPrivateKey.PrivateExponent.ToByteArrayUnsigned(),
                    P = rsaPrivateKey.Prime1.ToByteArrayUnsigned(),
                    Q = rsaPrivateKey.Prime2.ToByteArrayUnsigned(),
                    DP = rsaPrivateKey.Exponent1.ToByteArrayUnsigned(),
                    DQ = rsaPrivateKey.Exponent2.ToByteArrayUnsigned(),
                    InverseQ = rsaPrivateKey.Coefficient.ToByteArrayUnsigned()
                };

                rsa.ImportParameters(rsaParams);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("使用BouncyCastle导入PKCS8私钥失败", ex);
            }
        }

        /// <summary>
        /// 使用BouncyCastle导入SubjectPublicKeyInfo公钥（.NET Standard 2.1兼容）
        /// </summary>
        private static void ImportSubjectPublicKeyInfoUsingBouncyCastle(RSA rsa, byte[] keyBytes)
        {
            try
            {
                var publicKeyInfo = SubjectPublicKeyInfo.GetInstance(keyBytes);
                var rsaPublicKey = RsaPublicKeyStructure.GetInstance(publicKeyInfo.ParsePublicKey());

                var rsaParams = new RSAParameters
                {
                    Modulus = rsaPublicKey.Modulus.ToByteArrayUnsigned(),
                    Exponent = rsaPublicKey.PublicExponent.ToByteArrayUnsigned()
                };

                rsa.ImportParameters(rsaParams);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("使用BouncyCastle导入SubjectPublicKeyInfo公钥失败", ex);
            }
        }

        #endregion

        #region 密钥格式转换与辅助方法

        /// <summary>
        /// PKCS1格式转PKCS8格式
        /// </summary>
        public static string ConvertPkcs1ToPkcs8(string pkcs1Key, bool isPrivateKey)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(PemToRSAKey(pkcs1Key, isPrivateKey));
            return isPrivateKey ? ExportPrivateKey(rsa, RSAKeyFormat.PKCS8) : ExportPublicKey(rsa, RSAKeyFormat.PKCS8);
        }

        /// <summary>
        /// PKCS8格式转PKCS1格式
        /// </summary>
        public static string ConvertPkcs8ToPkcs1(string pkcs8Key, bool isPrivateKey)
        {
            using var rsa = RSA.Create();
            if (isPrivateKey)
            {
                ImportPkcs8PrivateKey(rsa, pkcs8Key);
            }
            else
            {
                ImportSubjectPublicKeyInfo(rsa, pkcs8Key);
            }
            return RSAKeyToPem(rsa.ToXmlString(isPrivateKey), isPrivateKey);
        }


        /// <summary>
        /// 智能密钥格式转换
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="targetFormat">目标格式</param>
        /// <param name="targetOutputFormat">目标输出格式</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <returns>转换后的密钥</returns>
        public static string ConvertKeyFormat(string key, RSAKeyFormat targetFormat, RSAOutputFormat targetOutputFormat, bool isPrivateKey)
        {
            if (string.IsNullOrEmpty(key))
                throw new ArgumentException("密钥不能为空", nameof(key));

            var sourceFormat = DetectKeyFormat(key);
            if (sourceFormat == targetFormat && targetOutputFormat == RSAOutputFormat.Base64)
                return key; // 无需转换

            using var rsa = RSA.Create();
            
            // 导入密钥
            if (isPrivateKey)
            {
                ImportPrivateKey(rsa, key, sourceFormat);
            }
            else
            {
                ImportPublicKey(rsa, key, sourceFormat);
            }

            // 导出到目标格式
            return isPrivateKey ? 
                ExportPrivateKey(rsa, targetFormat, targetOutputFormat) : 
                ExportPublicKey(rsa, targetFormat, targetOutputFormat);
        }

        /// <summary>
        /// 智能加密（自动检测密钥格式）
        /// </summary>
        /// <param name="input">输入数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>加密结果</returns>
        public static string SmartEncrypt(string input, string publicKey, RSAPaddingMode padding = RSAPaddingMode.PKCS1,
            RSAInputFormat inputFormat = RSAInputFormat.String, RSAOutputFormat outputFormat = RSAOutputFormat.Base64, 
            RSAEncoding encoding = RSAEncoding.UTF8)
        {
            var keyFormat = DetectKeyFormat(publicKey);
            return EncryptByRSA(input, publicKey, keyFormat, padding, inputFormat, outputFormat, encoding);
        }

        /// <summary>
        /// 智能解密（自动检测密钥格式）
        /// </summary>
        /// <param name="input">输入密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>解密结果</returns>
        public static string SmartDecrypt(string input, string privateKey, RSAPaddingMode padding = RSAPaddingMode.PKCS1,
            RSAInputFormat inputFormat = RSAInputFormat.Base64, RSAOutputFormat outputFormat = RSAOutputFormat.String,
            RSAEncoding encoding = RSAEncoding.UTF8)
        {
            var keyFormat = DetectKeyFormat(privateKey);
            return DecryptByRSA(input, privateKey, keyFormat, padding, inputFormat, outputFormat, encoding);
        }

        /// <summary>
        /// 智能签名（自动检测密钥格式）
        /// </summary>
        /// <param name="input">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>签名结果</returns>
        public static string SmartSign(string input, string privateKey, RSASignatureAlgorithm algorithm = RSASignatureAlgorithm.SHA256,
            RSAInputFormat inputFormat = RSAInputFormat.String, RSAOutputFormat outputFormat = RSAOutputFormat.Base64,
            RSAEncoding encoding = RSAEncoding.UTF8)
        {
            var keyFormat = DetectKeyFormat(privateKey);
            return HashAndSignString(input, privateKey, algorithm, keyFormat, inputFormat, outputFormat, encoding);
        }

        /// <summary>
        /// 智能验签（自动检测密钥格式）
        /// </summary>
        /// <param name="input">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="signatureFormat">签名格式</param>
        /// <param name="encoding">字符集编码</param>
        /// <returns>验证结果</returns>
        public static bool SmartVerify(string input, string signature, string publicKey, RSASignatureAlgorithm algorithm = RSASignatureAlgorithm.SHA256,
            RSAInputFormat inputFormat = RSAInputFormat.String, RSAInputFormat signatureFormat = RSAInputFormat.Base64,
            RSAEncoding encoding = RSAEncoding.UTF8)
        {
            var keyFormat = DetectKeyFormat(publicKey);
            return VerifySigned(input, signature, publicKey, algorithm, keyFormat, inputFormat, signatureFormat, encoding);
        }

        /// <summary>
        /// 从PEM格式字符串中提取密钥的Base64部分
        /// </summary>
        private static byte[] ExtractKeyBytesFromPem(string pemKey)
        {
            if (!pemKey.Contains("-----BEGIN")) return Convert.FromBase64String(pemKey);
            
            var lines = pemKey.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var base64 = string.Join("", lines.Skip(1).Take(lines.Length - 2));
            return Convert.FromBase64String(base64);
        }
        
        /// <summary>
        /// 将Base64字符串格式化为标准PEM格式
        /// </summary>
        private static string FormatPem(string base64Key, string keyType)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {keyType}-----");
            for (var i = 0; i < base64Key.Length; i += 64)
            {
                sb.AppendLine(base64Key.Substring(i, Math.Min(64, base64Key.Length - i)));
            }
            sb.AppendLine($"-----END {keyType}-----");
            return sb.ToString();
        }

        #endregion


        #region pfx和pem证书相关

        /// <summary>
        /// 根据pfx证书验签
        /// </summary>
        public static bool VerifySignByPfx(string filePath, string password, string noSignData, string signAlgorithm, string signData)
        {
            try
            {
                using var cert = new X509Certificate2(filePath, password);
                using var rsa = cert.GetRSAPublicKey() ?? throw new InvalidOperationException("证书不包含RSA公钥。");

                byte[] messageBytes = Encoding.UTF8.GetBytes(noSignData);
                byte[] signatureBytes = Convert.FromBase64String(signData);
                
                return rsa.VerifyData(messageBytes, signatureBytes, GetHashAlgorithmName(signAlgorithm), RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("PFX验签失败。", ex);
            }
        }

        /// <summary>
        /// 根据pfx证书加签
        /// </summary>
        public static string SignDataByPfx(byte[] pfxByte, string password, string noSignData, string signAlgorithm)
        {
            try
            {
                using var cert = new X509Certificate2(pfxByte, password);
                using var rsa = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("证书不包含RSA私钥或无法访问。");

                byte[] dataBytes = Encoding.UTF8.GetBytes(noSignData);
                byte[] signBytes = rsa.SignData(dataBytes, GetHashAlgorithmName(signAlgorithm), RSASignaturePadding.Pkcs1);
                
                return Convert.ToBase64String(signBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("PFX加签失败。", ex);
            }
        }

        /// <summary>
        /// 根据pfx证书加签
        /// </summary>
        public static string SignDataByPfx(string filePath, string password, string noSignData, string signAlgorithm)
        {
            try
            {
                using var cert = new X509Certificate2(filePath, password);
                using var rsa = cert.GetRSAPrivateKey() ?? throw new InvalidOperationException("证书不包含RSA私钥或无法访问。");

                byte[] dataBytes = Encoding.UTF8.GetBytes(noSignData);
                byte[] signBytes = rsa.SignData(dataBytes, GetHashAlgorithmName(signAlgorithm), RSASignaturePadding.Pkcs1);
                
                return Convert.ToBase64String(signBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("PFX加签失败。", ex);
            }
        }

        /// <summary>
        /// 根据pem证书验签
        /// </summary>
        public static bool VerifySignByPem(byte[] pemByte, string noSignData, string signAlgorithm, string signData)
        {
            return VerifySignByPem(Encoding.UTF8.GetString(pemByte), noSignData, signAlgorithm, signData);
        }

        /// <summary>
        /// 根据pem证书验签
        /// </summary>
        public static bool VerifySignByPem(string pemPathOrKey, string noSignData, string signAlgorithm, string signData)
        {
            try
            {
                string publicKeyPem = File.Exists(pemPathOrKey) ? File.ReadAllText(pemPathOrKey) : pemPathOrKey;
                
                using var rsa = RSA.Create();
                // 尝试直接导入PEM格式密钥
                try
                {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                    rsa.ImportFromPem(publicKeyPem);
#else
                    // .NET Standard 2.1兼容方式
                    if (publicKeyPem.Contains("BEGIN CERTIFICATE"))
                    {
                        // 处理证书格式
                        var cert = new X509Certificate2(Encoding.UTF8.GetBytes(publicKeyPem));
                        using var certRsa = cert.GetRSAPublicKey();
                        if (certRsa != null)
                        {
                            rsa.ImportParameters(certRsa.ExportParameters(false));
                        }
                    }
                    else if (publicKeyPem.Contains("BEGIN PUBLIC KEY"))
                    {
                        // 处理PKCS8公钥格式
                        ImportSubjectPublicKeyInfo(rsa, publicKeyPem);
                    }
                    else if (publicKeyPem.Contains("BEGIN RSA PUBLIC KEY"))
                    {
                        // 处理PKCS1公钥格式
                        rsa.FromXmlString(PemToRSAKey(publicKeyPem, false));
                    }
                    else
                    {
                        throw new ArgumentException("不支持的PEM格式");
                    }
#endif
                }
                catch
                {
                    // 如果直接导入失败，尝试其他格式
                    if (publicKeyPem.Contains("BEGIN RSA PUBLIC KEY"))
                    {
                        rsa.FromXmlString(PemToRSAKey(publicKeyPem, false));
                    }
                    else
                    {
                        throw;
                    }
                }
                
                byte[] messageBytes = Encoding.UTF8.GetBytes(noSignData);
                byte[] signatureBytes = Convert.FromBase64String(signData);
                
                return rsa.VerifyData(messageBytes, signatureBytes, GetHashAlgorithmName(signAlgorithm), RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("PEM验签失败。", ex);
            }
        }

        /// <summary>
        /// 根据pem证书加签
        /// </summary>
        public static string SignDataByPem(string pemPathOrKey, string noSignData, string signAlgorithm)
        {
            try
            {
                string privateKeyPem = File.Exists(pemPathOrKey) ? File.ReadAllText(pemPathOrKey) : pemPathOrKey;

                using var rsa = RSA.Create();
                // 尝试直接导入PEM格式密钥
                try
                {
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                    rsa.ImportFromPem(privateKeyPem);
#else
                    // .NET Standard 2.1兼容方式
                    if (privateKeyPem.Contains("BEGIN PRIVATE KEY"))
                    {
                        // 处理PKCS8私钥格式
                        ImportPkcs8PrivateKey(rsa, privateKeyPem);
                    }
                    else if (privateKeyPem.Contains("BEGIN RSA PRIVATE KEY"))
                    {
                        // 处理PKCS1私钥格式
                        rsa.FromXmlString(PemToRSAKey(privateKeyPem, true));
                    }
                    else
                    {
                        throw new ArgumentException("不支持的PEM格式");
                    }
#endif
                }
                catch
                {
                    // 如果直接导入失败，尝试其他格式
                    if (privateKeyPem.Contains("BEGIN RSA PRIVATE KEY"))
                    {
                        rsa.FromXmlString(PemToRSAKey(privateKeyPem, true));
                    }
                    else
                    {
                        throw;
                    }
                }

                byte[] dataBytes = Encoding.UTF8.GetBytes(noSignData);
                byte[] signBytes = rsa.SignData(dataBytes, GetHashAlgorithmName(signAlgorithm), RSASignaturePadding.Pkcs1);
                
                return Convert.ToBase64String(signBytes);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("PEM加签失败。", ex);
            }
        }

        /// <summary>
        /// 生成自签名的pfx证书
        /// </summary>
        public static void GeneratePfxCertificate(string pfxPath, string password = "123456")
        {
            var caPrivKey = GenerateCACertificate("CN=root ca");
            var cert = GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=root ca", caPrivKey);
            byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);
            File.WriteAllBytes(pfxPath, pfxBytes);
        }

        /// <summary>
        /// 生成证书对象数据
        /// </summary>
        public static X509Certificate2 GetX509Certificate2()
        {
            var caPrivKey = GenerateCACertificate("CN=root ca");
            return GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=root ca", caPrivKey);
        }

        /// <summary>
        /// 生成公有pem证书
        /// </summary>
        public static void GeneratePublicPemCert(X509Certificate2 x509, string pemPublicPath)
        {
            using var rsa = x509.GetRSAPublicKey() ?? throw new InvalidOperationException("证书不包含RSA公钥。");
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
            string pemPublicKey = rsa.ExportSubjectPublicKeyInfoPem();
#else
            // .NET Standard 2.1兼容方式
            byte[] publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
            string pemPublicKey = FormatPem(Convert.ToBase64String(publicKeyBytes), "PUBLIC KEY");
#endif
            File.WriteAllText(pemPublicPath, pemPublicKey, Encoding.UTF8);
        }

        /// <summary>
        /// 生成私有pem证书
        /// </summary>
        public static void GeneratePrivatePemCert(X509Certificate2 x509, string pemPrivatePath)
        {
            using var rsa = x509.GetRSAPrivateKey() ?? throw new InvalidOperationException("证书不包含RSA私钥或无法访问。");
#if NETCOREAPP3_0_OR_GREATER || NET5_0_OR_GREATER
                string pemPrivateKey = rsa.ExportPkcs8PrivateKeyPem();
#else
            // .NET Standard 2.1兼容方式
            byte[] privateKeyBytes = ExportPkcs8PrivateKeyBytes(rsa);
            string pemPrivateKey = FormatPem(Convert.ToBase64String(privateKeyBytes), "PRIVATE KEY");
#endif
            File.WriteAllText(pemPrivatePath, pemPrivateKey, Encoding.UTF8);
        }

        private static HashAlgorithmName GetHashAlgorithmName(string signAlgorithm) => signAlgorithm.ToUpperInvariant() switch
        {
            "SHA1" => HashAlgorithmName.SHA1,
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            "MD5" => HashAlgorithmName.MD5,
            _ => throw new ArgumentException($"不支持的签名算法: {signAlgorithm}", nameof(signAlgorithm)),
        };

        #endregion

        #region BouncyCastle 兼容方法 (XML <-> PEM)

        /// <summary>
        /// RSA密钥(XML)转Pem密钥
        /// </summary>
        public static string RSAKeyToPem(string rsaXmlKey, bool isPrivateKey)
        {
            using var rsa = RSA.Create();
            rsa.FromXmlString(rsaXmlKey);
            
            RSAParameters rsaPara = rsa.ExportParameters(isPrivateKey);
            AsymmetricKeyParameter key = isPrivateKey
                ? new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent), new BigInteger(1, rsaPara.D),
                    new BigInteger(1, rsaPara.P), new BigInteger(1, rsaPara.Q), new BigInteger(1, rsaPara.DP), new BigInteger(1, rsaPara.DQ),
                    new BigInteger(1, rsaPara.InverseQ))
                : new RsaKeyParameters(false, new BigInteger(1, rsaPara.Modulus), new BigInteger(1, rsaPara.Exponent));

            using var sw = new StringWriter();
            var pemWriter = new PemWriter(sw);
            pemWriter.WriteObject(key);
            return sw.ToString();
        }

        /// <summary>
        /// Pem密钥转RSA密钥(XML)
        /// </summary>
        public static string PemToRSAKey(string pemKey, bool isPrivateKey)
        {
            using var sReader = new StringReader(pemKey);
            var pemObject = new PemReader(sReader).ReadObject();

            RSAParameters rsaPara;
            if (isPrivateKey)
            {
                var key = (RsaPrivateCrtKeyParameters)((AsymmetricCipherKeyPair)pemObject).Private;
                rsaPara = new RSAParameters
                {
                    Modulus = key.Modulus.ToByteArrayUnsigned(), Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                    D = key.Exponent.ToByteArrayUnsigned(), P = key.P.ToByteArrayUnsigned(), Q = key.Q.ToByteArrayUnsigned(),
                    DP = key.DP.ToByteArrayUnsigned(), DQ = key.DQ.ToByteArrayUnsigned(), InverseQ = key.QInv.ToByteArrayUnsigned(),
                };
            }
            else
            {
                var key = (RsaKeyParameters)pemObject;
                rsaPara = new RSAParameters { Modulus = key.Modulus.ToByteArrayUnsigned(), Exponent = key.Exponent.ToByteArrayUnsigned() };
            }
            
            using var rsa = RSA.Create();
            rsa.ImportParameters(rsaPara);
            return rsa.ToXmlString(isPrivateKey);
        }


        #endregion


        #region 生成自签名证书


        /// <summary>
        /// 生成自签名证书
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="issuerName"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName)
        {
            const int keyStrength = 2048;

            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            X509Name subjectDN = new X509Name(subjectName);
            X509Name issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;

            // https://stackoverflow.com/questions/60547020/c-sharp-generate-intermediate-certificate-from-self-signed-root-ca
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerKeyPair.Private, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);
            // https://stackoverflow.com/questions/36942094/how-can-i-generate-a-self-signed-cert-without-using-obsolete-bouncycastle-1-7-0
            //Org.BouncyCastle.X509.X509Certificate certificate = certificateGenerator.Generate(issuerPrivKey, random);


            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // merge into X509Certificate2
            X509Certificate2 x509 = new X509Certificate2(certificate.GetEncoded());
            Asn1Sequence seq = (Asn1Sequence)Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
            {
                throw new PemException("malformed sequence in RSA private key");
            }

            RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(seq);
            RsaPrivateCrtKeyParameters rsaParams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            // https://github.com/bcgit/bc-csharp/issues/160
            // https://stackoverflow.com/questions/54752834/error-setting-x509certificate2-privatekey
            // x509.PrivateKey = DotNetUtilities.ToRSA(rsaParams); 
            // return x509;
            // [DotNetUtilities class only works on Windows](https://github.com/bcgit/bc-csharp/issues/160)
            // if run on Linux will cause 'CspParameters' requires Windows Cryptographic API (CAPI), which is not available on this platform.
            // var cert = x509.CopyWithPrivateKey(DotNetUtilities.ToRSA(rsaParams));
            var parms = DotNetUtilities.ToRSAParameters(rsaParams);
            var rsaCreate = RSA.Create();
            rsaCreate.ImportParameters(parms);
            var cert = x509.CopyWithPrivateKey(rsaCreate);
            return cert;
        }

        /// <summary>
        /// 生成CA证书
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="CaPrivateKey"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateCACertificate(string subjectName, ref AsymmetricKeyParameter CaPrivateKey)
        {
            const int keyStrength = 2048;

            // Generating Random Numbers
            CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
            SecureRandom random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            BigInteger serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            X509Name subjectDN = new X509Name(subjectName);
            X509Name issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            DateTime notBefore = DateTime.UtcNow.Date;
            DateTime notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            RsaKeyPairGenerator keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            AsymmetricCipherKeyPair issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);
            X509Certificate2 x509 = new X509Certificate2(certificate.GetEncoded());

            CaPrivateKey = issuerKeyPair.Private;

            return x509;

        }

        /// <summary>
        /// 生成自签名证书
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="issuerName"></param>
        /// <param name="issuerPrivKey"></param>
        /// <param name="keyStrength"></param>
        /// <returns></returns>
        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            // var issuerKeyPair = subjectKeyPair;

            // https://stackoverflow.com/questions/60547020/c-sharp-generate-intermediate-certificate-from-self-signed-root-ca
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerPrivKey, random);
            // ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerKeyPair.Private, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);

            // Corresponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);


            // Merge into X509Certificate2
            var x509 = new X509Certificate2(certificate.GetEncoded());

            Asn1Sequence seq = (Asn1Sequence)Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
            {
                throw new PemException("malformed sequence in RSA private key");
            }

            RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(seq);
            RsaPrivateCrtKeyParameters rsaParams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            // https://github.com/bcgit/bc-csharp/issues/160
            // https://stackoverflow.com/questions/54752834/error-setting-x509certificate2-privatekey
            // x509.PrivateKey = DotNetUtilities.ToRSA(rsaParams); 
            // return x509;
            // [DotNetUtilities class only works on Windows](https://github.com/bcgit/bc-csharp/issues/160)
            // if run on Linux will cause 'CspParameters' requires Windows Cryptographic API (CAPI), which is not available on this platform.
            // var cert = x509.CopyWithPrivateKey(DotNetUtilities.ToRSA(rsaParams));
            var parms = DotNetUtilities.ToRSAParameters(rsaParams);
            var rsaCreate = RSA.Create();
            rsaCreate.ImportParameters(parms);
            var cert = x509.CopyWithPrivateKey(rsaCreate);
            return cert;
        }

        /// <summary>
        /// 生成CA证书
        /// </summary>
        /// <param name="subjectName"></param>
        /// <param name="keyStrength"></param>
        /// <returns></returns>
        public static AsymmetricKeyParameter GenerateCACertificate(string subjectName, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // selfsign certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), issuerKeyPair.Private, random);
            var certificate = certificateGenerator.Generate(signatureFactory);
            X509Certificate2 x509 = new X509Certificate2(certificate.GetEncoded());

            return issuerKeyPair.Private;
            // return x509;
        }

        #endregion

    }
}
