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
        /// RSA密钥类型
        /// </summary>
        public enum RSAKeyType
        {
            PKCS1,
            PKCS8
        }

        /// <summary>
        /// RSA填充方式
        /// </summary>
        public enum RSAPadding
        {
            PKCS1,
            OAEP,
            NoPadding
        }

        /// <summary>
        /// 密钥格式
        /// </summary>
        public enum RSAKeyFormat
        {
            PEM,
            Base64,
            Hex
        }

        /// <summary>
        /// 签名算法
        /// </summary>
        public enum SignatureAlgorithm
        {
            /// <summary>
            /// 又称RSA1
            /// </summary>
            SHA1withRSA,
            /// <summary>
            /// 又称RSA2
            /// </summary>
            SHA256withRSA,
            SHA384withRSA,
            SHA512withRSA,
            MD5withRSA
        }

        #endregion

        #region 密钥生成

        /// <summary>
        /// 生成RSA密钥对
        /// </summary>
        /// <param name="keySize">密钥长度（1024、2048、4096）</param>
        /// <returns>密钥对</returns>
        public static AsymmetricCipherKeyPair GenerateKeyPair(int keySize = 2048)
        {
            if (keySize != 1024 && keySize != 2048 && keySize != 4096)
                throw new ArgumentException("密钥长度只支持1024、2048、4096位");

            var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), keySize);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        /// <summary>
        /// 生成公钥字符串
        /// </summary>
        /// <param name="publicKey">公钥对象</param>
        /// <param name="format">输出格式</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>公钥字符串</returns>
        public static string GeneratePublicKeyString(RsaKeyParameters publicKey, RSAKeyFormat format = RSAKeyFormat.PEM, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            switch (format)
            {
                case RSAKeyFormat.PEM:
                    return PublicKeyToPem(publicKey, keyFormat);
                case RSAKeyFormat.Base64:
                    return PublicKeyToBase64(publicKey, keyFormat);
                case RSAKeyFormat.Hex:
                    return PublicKeyToHex(publicKey, keyFormat);
                default:
                    throw new ArgumentException($"不支持的输出格式[{format}]");
            }
        }

        /// <summary>
        /// 生成私钥字符串
        /// </summary>
        /// <param name="privateKey">私钥对象</param>
        /// <param name="format">输出格式</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>私钥字符串</returns>
        public static string GeneratePrivateKeyString(RsaPrivateCrtKeyParameters privateKey, RSAKeyFormat format = RSAKeyFormat.PEM, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            switch (format)
            {
                case RSAKeyFormat.PEM:
                    return PrivateKeyToPem(privateKey, keyFormat);
                case RSAKeyFormat.Base64:
                    return PrivateKeyToBase64(privateKey, keyFormat);
                case RSAKeyFormat.Hex:
                    return PrivateKeyToHex(privateKey, keyFormat);
                default:
                    throw new ArgumentException($"不支持的输出格式[{format}]");
            }
        }

        #endregion

        #region 密钥格式转换

        /// <summary>
        /// 公钥转PEM格式
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>PEM格式公钥</returns>
        public static string PublicKeyToPem(RsaKeyParameters publicKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                if (keyFormat == RSAKeyType.PKCS1)
                {
                    // PKCS#1 PEM for public key is non-standard but supported by BouncyCastle
                    // It actually writes an RsaPublicKeyStructure
                    var rsaPublicKey = new RsaPublicKeyStructure(publicKey.Modulus, publicKey.Exponent);
                    pemWriter.WriteObject(rsaPublicKey);
                }
                else
                {
                    var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                    pemWriter.WriteObject(publicKeyInfo);
                }
                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// 私钥转PEM格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>PEM格式私钥</returns>
        public static string PrivateKeyToPem(RsaPrivateCrtKeyParameters privateKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                if (keyFormat == RSAKeyType.PKCS1)
                {
                    pemWriter.WriteObject(privateKey);
                }
                else
                {
                    var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
                    pemWriter.WriteObject(privateKeyInfo);
                }
                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// 公钥转Base64格式
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>Base64格式公钥</returns>
        public static string PublicKeyToBase64(RsaKeyParameters publicKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            byte[] keyBytes;
            if (keyFormat == RSAKeyType.PKCS1)
            {
                var rsaPublicKeyStructure = new RsaPublicKeyStructure(publicKey.Modulus, publicKey.Exponent);
                keyBytes = rsaPublicKeyStructure.GetDerEncoded();
            }
            else
            {
                var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                keyBytes = publicKeyInfo.GetDerEncoded();
            }
            return Convert.ToBase64String(keyBytes);
        }

        /// <summary>
        /// 私钥转Base64格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>Base64格式私钥</returns>
        public static string PrivateKeyToBase64(RsaPrivateCrtKeyParameters privateKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            byte[] keyBytes;
            if (keyFormat == RSAKeyType.PKCS1)
            {
                var rsaPrivateKeyStructure = new RsaPrivateKeyStructure(
                    privateKey.Modulus, privateKey.PublicExponent, privateKey.Exponent,
                    privateKey.P, privateKey.Q, privateKey.DP, privateKey.DQ, privateKey.QInv);
                keyBytes = rsaPrivateKeyStructure.GetDerEncoded();
            }
            else
            {
                var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
                keyBytes = privateKeyInfo.GetDerEncoded();
            }
            return Convert.ToBase64String(keyBytes);
        }

        /// <summary>
        /// 公钥转Hex格式
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>Hex格式公钥</returns>
        public static string PublicKeyToHex(RsaKeyParameters publicKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var base64Key = PublicKeyToBase64(publicKey, keyFormat);
            var keyBytes = Convert.FromBase64String(base64Key);
            return BitConverter.ToString(keyBytes).Replace("-", "");
        }

        /// <summary>
        /// 私钥转Hex格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>Hex格式私钥</returns>
        public static string PrivateKeyToHex(RsaPrivateCrtKeyParameters privateKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var base64Key = PrivateKeyToBase64(privateKey, keyFormat);
            var keyBytes = Convert.FromBase64String(base64Key);
            return BitConverter.ToString(keyBytes).Replace("-", "");
        }

        #endregion

        #region 密钥解析

        /// <summary>
        /// 从PEM格式解析公钥
        /// </summary>
        /// <param name="pemKey">PEM格式公钥</param>
        /// <returns>公钥对象</returns>
        public static RsaKeyParameters ParsePublicKeyFromPem(string pemKey)
        {
            using (var stringReader = new StringReader(pemKey))
            {
                var pemReader = new PemReader(stringReader);
                var keyObj = pemReader.ReadObject();

                if (keyObj is RsaKeyParameters rsaKey)
                {
                    return rsaKey;
                }
                else if (keyObj is SubjectPublicKeyInfo publicKeyInfo)
                {
                    return (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
                }
                // BouncyCastle can read a PKCS#1 public key PEM as RsaPublicKeyStructure
                else if (keyObj is RsaPublicKeyStructure rsaPublicKey)
                {
                    return new RsaKeyParameters(false, rsaPublicKey.Modulus, rsaPublicKey.PublicExponent);
                }
                else
                {
                    throw new ArgumentException("无效的PEM格式公钥");
                }
            }
        }

        /// <summary>
        /// 从PEM格式解析私钥
        /// </summary>
        /// <param name="pemKey">PEM格式私钥</param>
        /// <returns>私钥对象</returns>
        public static RsaPrivateCrtKeyParameters ParsePrivateKeyFromPem(string pemKey)
        {
            using (var stringReader = new StringReader(pemKey))
            {
                var pemReader = new PemReader(stringReader);
                var keyObj = pemReader.ReadObject();

                if (keyObj is RsaPrivateCrtKeyParameters rsaPrivateKey)
                {
                    return rsaPrivateKey;
                }
                // AsymmetricCipherKeyPair can be returned for PKCS#1 private keys
                else if (keyObj is AsymmetricCipherKeyPair keyPair)
                {
                    return (RsaPrivateCrtKeyParameters)keyPair.Private;
                }
                else if (keyObj is PrivateKeyInfo privateKeyInfo)
                {
                    return (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                }
                else
                {
                    throw new ArgumentException("无效的PEM格式私钥");
                }
            }
        }

        /// <summary>
        /// 从Base64格式解析公钥
        /// </summary>
        /// <param name="base64Key">Base64格式公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>公钥对象</returns>
        public static RsaKeyParameters ParsePublicKeyFromBase64(string base64Key, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var keyBytes = Convert.FromBase64String(base64Key);
            return ParsePublicKeyFromBytes(keyBytes, keyFormat);
        }

        /// <summary>
        /// 从Base64格式解析私钥
        /// </summary>
        /// <param name="base64Key">Base64格式私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>私钥对象</returns>
        public static RsaPrivateCrtKeyParameters ParsePrivateKeyFromBase64(string base64Key, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var keyBytes = Convert.FromBase64String(base64Key);
            return ParsePrivateKeyFromBytes(keyBytes, keyFormat);
        }

        /// <summary>
        /// 从Hex格式解析公钥
        /// </summary>
        /// <param name="hexKey">Hex格式公钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>公钥对象</returns>
        public static RsaKeyParameters ParsePublicKeyFromHex(string hexKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var keyBytes = HexStringToBytes(hexKey);
            return ParsePublicKeyFromBytes(keyBytes, keyFormat);
        }

        /// <summary>
        /// 从Hex格式解析私钥
        /// </summary>
        /// <param name="hexKey">Hex格式私钥</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>私钥对象</returns>
        public static RsaPrivateCrtKeyParameters ParsePrivateKeyFromHex(string hexKey, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            var keyBytes = HexStringToBytes(hexKey);
            return ParsePrivateKeyFromBytes(keyBytes, keyFormat);
        }

        /// <summary>
        /// 从字节数组解析公钥
        /// </summary>
        /// <param name="keyBytes">密钥字节数组</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>公钥对象</returns>
        public static RsaKeyParameters ParsePublicKeyFromBytes(byte[] keyBytes, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            try
            {
                if (keyFormat == RSAKeyType.PKCS1)
                {
                    var asn1Object = Asn1Object.FromByteArray(keyBytes);
                    var rsaPublicKey = RsaPublicKeyStructure.GetInstance(asn1Object);
                    return new RsaKeyParameters(false, rsaPublicKey.Modulus, rsaPublicKey.PublicExponent);
                }
                else
                {
                    var publicKeyInfo = SubjectPublicKeyInfo.GetInstance(keyBytes);
                    return (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"无法将字节数组解析为 {keyFormat} 格式的公钥。请检查密钥格式和内容。", ex);
            }
        }

        /// <summary>
        /// 从字节数组解析私钥
        /// </summary>
        /// <param name="keyBytes">密钥字节数组</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>私钥对象</returns>
        public static RsaPrivateCrtKeyParameters ParsePrivateKeyFromBytes(byte[] keyBytes, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            try
            {
                if (keyFormat == RSAKeyType.PKCS1)
                {
                    var asn1Object = Asn1Object.FromByteArray(keyBytes);
                    var rsaPrivateKey = RsaPrivateKeyStructure.GetInstance(asn1Object);
                    return new RsaPrivateCrtKeyParameters(
                        rsaPrivateKey.Modulus, rsaPrivateKey.PublicExponent, rsaPrivateKey.PrivateExponent,
                        rsaPrivateKey.Prime1, rsaPrivateKey.Prime2, rsaPrivateKey.Exponent1,
                        rsaPrivateKey.Exponent2, rsaPrivateKey.Coefficient);
                }
                else
                {
                    var privateKeyInfo = PrivateKeyInfo.GetInstance(keyBytes);
                    return (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"无法将字节数组解析为 {keyFormat} 格式的私钥。请检查密钥格式和内容。", ex);
            }
        }

        /// <summary>
        /// 统一解析密钥字符串为密钥对象
        /// </summary>
        /// <param name="key">密钥字符串（PEM/Base64/Hex）</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="inputFormat">密钥字符串格式</param>
        /// <param name="keyType">密钥类型（仅Base64/Hex时需要明确PKCS1或PKCS8；PEM可忽略）</param>
        /// <returns>密钥对象（RsaKeyParameters 或 RsaPrivateCrtKeyParameters）</returns>
        public static AsymmetricKeyParameter ParseKey(string key, bool isPrivateKey, RSAKeyFormat inputFormat = RSAKeyFormat.PEM, RSAKeyType keyType = RSAKeyType.PKCS1)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("密钥字符串不能为空");

            return inputFormat switch
            {
                RSAKeyFormat.PEM => isPrivateKey
                    ? (AsymmetricKeyParameter)ParsePrivateKeyFromPem(key)
                    : (AsymmetricKeyParameter)ParsePublicKeyFromPem(key),
                RSAKeyFormat.Base64 => isPrivateKey
                    ? ParsePrivateKeyFromBase64(key, keyType)
                    : (AsymmetricKeyParameter)ParsePublicKeyFromBase64(key, keyType),
                RSAKeyFormat.Hex => isPrivateKey
                    ? ParsePrivateKeyFromHex(key, keyType)
                    : (AsymmetricKeyParameter)ParsePublicKeyFromHex(key, keyType),
                _ => throw new ArgumentException($"不支持的密钥字符串格式[{inputFormat}]")
            };
        }

        #endregion

        #region 加解密

        /// <summary>
        /// RSA加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文</returns>
        public static string Encrypt(string plaintext, RsaKeyParameters publicKey, RSAPadding padding = RSAPadding.PKCS1, RSAKeyFormat outputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空");

            encoding = encoding ?? Encoding.UTF8;
            var plaintextBytes = encoding.GetBytes(plaintext);
            var ciphertextBytes = Encrypt(plaintextBytes, publicKey, padding);

            return outputFormat switch
            {
                RSAKeyFormat.Base64 => Convert.ToBase64String(ciphertextBytes),
                RSAKeyFormat.Hex => BytesToHexString(ciphertextBytes),
                _ => throw new ArgumentException($"不支持的输出格式[{outputFormat}]")
            };
        }

        /// <summary>
        /// 基于密钥字符串的RSA加密（PEM/Base64/Hex）
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKeyString">公钥字符串</param>
        /// <param name="keyStringFormat">公钥字符串格式（PEM/Base64/Hex）</param>
        /// <param name="keyType">密钥类型（PKCS1/PKCS8，用于Base64/Hex）</param>
        /// <param name="padding">填充方式</param>
        /// <param name="outputFormat">密文输出格式（Base64/Hex）</param>
        /// <param name="encoding">字符编码（默认UTF8）</param>
        /// <returns>密文</returns>
        public static string Encrypt(string plaintext, string publicKeyString, RSAKeyFormat keyStringFormat = RSAKeyFormat.PEM, RSAKeyType keyType = RSAKeyType.PKCS1, RSAPadding padding = RSAPadding.PKCS1, RSAKeyFormat outputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            var key = ParseKey(publicKeyString, false, keyStringFormat, keyType);
            if (!(key is RsaKeyParameters publicKey))
                throw new ArgumentException("提供的密钥不是有效的公钥");

            return Encrypt(plaintext, publicKey, padding, outputFormat, encoding);
        }

        /// <summary>
        /// RSA加密（字节数组）
        /// </summary>
        /// <param name="plaintext">明文字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] Encrypt(byte[] plaintext, RsaKeyParameters publicKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw new ArgumentException("明文不能为空");

            var engine = GetCipherEngine(padding);
            engine.Init(true, publicKey);
            return engine.ProcessBlock(plaintext, 0, plaintext.Length);
        }

        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        public static string Decrypt(string ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding = RSAPadding.PKCS1, RSAKeyFormat inputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("密文不能为空");

            encoding = encoding ?? Encoding.UTF8;

            byte[] ciphertextBytes = inputFormat switch
            {
                RSAKeyFormat.Base64 => Convert.FromBase64String(ciphertext),
                RSAKeyFormat.Hex => HexStringToBytes(ciphertext),
                _ => throw new ArgumentException($"不支持的输入格式{inputFormat}")
            };

            var plaintextBytes = Decrypt(ciphertextBytes, privateKey, padding);
            return encoding.GetString(plaintextBytes);
        }

        /// <summary>
        /// 基于密钥字符串的RSA解密（PEM/Base64/Hex）
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKeyString">私钥字符串</param>
        /// <param name="keyStringFormat">私钥字符串格式（PEM/Base64/Hex）</param>
        /// <param name="keyType">密钥类型（PKCS1/PKCS8，用于Base64/Hex）</param>
        /// <param name="padding">填充方式</param>
        /// <param name="inputFormat">密文输入格式（Base64/Hex）</param>
        /// <param name="encoding">字符编码（默认UTF8）</param>
        /// <returns>明文</returns>
        public static string Decrypt(string ciphertext, string privateKeyString, RSAKeyFormat keyStringFormat = RSAKeyFormat.PEM, RSAKeyType keyType = RSAKeyType.PKCS1, RSAPadding padding = RSAPadding.PKCS1, RSAKeyFormat inputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            var key = ParseKey(privateKeyString, true, keyStringFormat, keyType);
            if (!(key is RsaPrivateCrtKeyParameters privateKey))
                throw new ArgumentException("提供的密钥不是有效的私钥");

            return Decrypt(ciphertext, privateKey, padding, inputFormat, encoding);
        }

        /// <summary>
        /// RSA解密（字节数组）
// / </summary>
        /// <param name="ciphertext">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文字节数组</returns>
        public static byte[] Decrypt(byte[] ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("密文不能为空");

            var engine = GetCipherEngine(padding);
            engine.Init(false, privateKey);
            return engine.ProcessBlock(ciphertext, 0, ciphertext.Length);
        }

        #endregion

        #region 签名与验签

        /// <summary>
        /// RSA签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名</returns>
        public static string Sign(string data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, RSAKeyFormat outputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("待签名数据不能为空");

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = Sign(dataBytes, privateKey, algorithm);

            return outputFormat switch
            {
                RSAKeyFormat.Base64 => Convert.ToBase64String(signatureBytes),
                RSAKeyFormat.Hex => BytesToHexString(signatureBytes),
                _ => throw new ArgumentException($"不支持的输出格式[{outputFormat}]")
            };
        }

        /// <summary>
        /// 基于密钥字符串的RSA签名（PEM/Base64/Hex）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKeyString">私钥字符串</param>
        /// <param name="keyStringFormat">私钥字符串格式（PEM/Base64/Hex）</param>
        /// <param name="keyType">密钥类型（PKCS1/PKCS8，用于Base64/Hex）</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="outputFormat">签名输出格式（Base64/Hex）</param>
        /// <param name="encoding">字符编码（默认UTF8）</param>
        /// <returns>签名字符串</returns>
        public static string Sign(string data, string privateKeyString, RSAKeyFormat keyStringFormat = RSAKeyFormat.PEM, RSAKeyType keyType = RSAKeyType.PKCS1, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, RSAKeyFormat outputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            var key = ParseKey(privateKeyString, true, keyStringFormat, keyType);
            if (!(key is RsaPrivateCrtKeyParameters privateKey))
                throw new ArgumentException("提供的密钥不是有效的私钥");

            return Sign(data, privateKey, algorithm, outputFormat, encoding);
        }

        /// <summary>
        /// RSA签名（字节数组）
        /// </summary>
        /// <param name="data">待签名数据字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>签名字节数组</returns>
        public static byte[] Sign(byte[] data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("待签名数据不能为空");

            var algorithmName = GetSignatureAlgorithmName(algorithm);
            var signer = SignerUtilities.GetSigner(algorithmName);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// RSA验签
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验签结果</returns>
        public static bool Verify(string data, string signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, RSAKeyFormat inputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);

            byte[] signatureBytes = inputFormat switch
            {
                RSAKeyFormat.Base64 => Convert.FromBase64String(signature),
                RSAKeyFormat.Hex => HexStringToBytes(signature),
                _ => throw new ArgumentException($"不支持的输入格式[{inputFormat}]")
            };

            return Verify(dataBytes, signatureBytes, publicKey, algorithm);
        }

        /// <summary>
        /// 基于密钥字符串的RSA验签（PEM/Base64/Hex）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名字符串</param>
        /// <param name="publicKeyString">公钥字符串</param>
        /// <param name="keyStringFormat">公钥字符串格式（PEM/Base64/Hex）</param>
        /// <param name="keyType">密钥类型（PKCS1/PKCS8，用于Base64/Hex）</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="inputFormat">签名输入格式（Base64/Hex）</param>
        /// <param name="encoding">字符编码（默认UTF8）</param>
        /// <returns>验签结果</returns>
        public static bool Verify(string data, string signature, string publicKeyString, RSAKeyFormat keyStringFormat = RSAKeyFormat.PEM, RSAKeyType keyType = RSAKeyType.PKCS1, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, RSAKeyFormat inputFormat = RSAKeyFormat.Base64, Encoding encoding = null)
        {
            var key = ParseKey(publicKeyString, false, keyStringFormat, keyType);
            if (!(key is RsaKeyParameters publicKey))
                throw new ArgumentException("提供的密钥不是有效的公钥");

            return Verify(data, signature, publicKey, algorithm, inputFormat, encoding);
        }

        /// <summary>
        /// RSA验签（字节数组）
        /// </summary>
        /// <param name="data">原始数据字节数组</param>
        /// <param name="signature">签名字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>验签结果</returns>
        public static bool Verify(byte[] data, byte[] signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            if (data == null || signature == null || data.Length == 0 || signature.Length == 0)
                return false;

            var algorithmName = GetSignatureAlgorithmName(algorithm);
            var signer = SignerUtilities.GetSigner(algorithmName);
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }

        #endregion

        #region 证书处理

        /// <summary>
        /// 生成自签名证书
        /// </summary>
        /// <param name="keyPair">密钥对</param>
        /// <param name="subject">证书主题</param>
        /// <param name="validFrom">有效期开始时间</param>
        /// <param name="validTo">有效期结束时间</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>X509证书</returns>
        public static X509Certificate2 GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair, string subject, DateTime validFrom, DateTime validTo, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            var algorithmName = GetSignatureAlgorithmName(algorithm);
            var signatureFactory = new Asn1SignatureFactory(algorithmName, keyPair.Private);

            var certGen = new X509V3CertificateGenerator();
            var serialNumber = BigInteger.ProbablePrime(120, new Random());
            
            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(new X509Name(subject));
            certGen.SetSubjectDN(new X509Name(subject));
            certGen.SetNotBefore(validFrom);
            certGen.SetNotAfter(validTo);
            certGen.SetPublicKey(keyPair.Public);

            var certificate = certGen.Generate(signatureFactory);
            
            // 转换为.NET证书
            var pfx = new Pkcs12StoreBuilder().Build();
            var certEntry = new X509CertificateEntry(certificate);
            var keyEntry = new AsymmetricKeyEntry(keyPair.Private);
            
            pfx.SetCertificateEntry("cert", certEntry);
            pfx.SetKeyEntry("key", keyEntry, new X509CertificateEntry[] { certEntry });

            using (var stream = new MemoryStream())
            {
                pfx.Save(stream, new char[0], new SecureRandom());
                return new X509Certificate2(stream.ToArray(), "", X509KeyStorageFlags.Exportable);
            }
        }

        /// <summary>
        /// 从证书导出公钥
        /// </summary>
        /// <param name="certificate">X509证书</param>
        /// <param name="format">输出格式</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>公钥字符串</returns>
        public static string ExportPublicKeyFromCertificate(X509Certificate2 certificate, RSAKeyFormat format = RSAKeyFormat.PEM, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            using (var rsa = certificate.GetRSAPublicKey())
            {
                var parameters = rsa.ExportParameters(false);
                var publicKey = new RsaKeyParameters(false, new BigInteger(1, parameters.Modulus), new BigInteger(1, parameters.Exponent));
                return GeneratePublicKeyString(publicKey, format, keyFormat);
            }
        }

        /// <summary>
        /// 从证书导出私钥
        /// </summary>
        /// <param name="certificate">X509证书</param>
        /// <param name="format">输出格式</param>
        /// <param name="keyFormat">密钥格式</param>
        /// <returns>私钥字符串</returns>
        public static string ExportPrivateKeyFromCertificate(X509Certificate2 certificate, RSAKeyFormat format = RSAKeyFormat.PEM, RSAKeyType keyFormat = RSAKeyType.PKCS1)
        {
            if (!certificate.HasPrivateKey)
                throw new InvalidOperationException("证书不包含私钥");

            using (var rsa = certificate.GetRSAPrivateKey())
            {
                var parameters = rsa.ExportParameters(true);
                var privateKey = new RsaPrivateCrtKeyParameters(
                    new BigInteger(1, parameters.Modulus),
                    new BigInteger(1, parameters.Exponent),
                    new BigInteger(1, parameters.D),
                    new BigInteger(1, parameters.P),
                    new BigInteger(1, parameters.Q),
                    new BigInteger(1, parameters.DP),
                    new BigInteger(1, parameters.DQ),
                    new BigInteger(1, parameters.InverseQ));
                return GeneratePrivateKeyString(privateKey, format, keyFormat);
            }
        }

        /// <summary>
        /// 导出证书为PEM格式
        /// </summary>
        /// <param name="certificate">X509证书</param>
        /// <returns>PEM格式证书</returns>
        public static string ExportCertificateToPem(X509Certificate2 certificate)
        {
            var base64 = Convert.ToBase64String(certificate.RawData);
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            
            for (int i = 0; i < base64.Length; i += 64)
            {
                var line = base64.Substring(i, Math.Min(64, base64.Length - i));
                sb.AppendLine(line);
            }
            
            sb.AppendLine("-----END CERTIFICATE-----");
            return sb.ToString();
        }

        #endregion

        #region 格式转换

        /// <summary>
        /// PKCS1转PKCS8格式
        /// </summary>
        /// <param name="pkcs1Key">PKCS1格式密钥</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>PKCS8格式密钥</returns>
        public static string ConvertPkcs1ToPkcs8(string pkcs1Key, bool isPrivateKey, RSAKeyFormat inputFormat = RSAKeyFormat.PEM, RSAKeyFormat outputFormat = RSAKeyFormat.PEM)
        {
            if (isPrivateKey)
            {
                var privateKey = inputFormat switch
                {
                    RSAKeyFormat.PEM => ParsePrivateKeyFromPem(pkcs1Key),
                    RSAKeyFormat.Base64 => ParsePrivateKeyFromBase64(pkcs1Key, RSAKeyType.PKCS1),
                    RSAKeyFormat.Hex => ParsePrivateKeyFromHex(pkcs1Key, RSAKeyType.PKCS1),
                    _ => throw new ArgumentException("不支持的输入格式")
                };
                return GeneratePrivateKeyString(privateKey, outputFormat, RSAKeyType.PKCS8);
            }
            else
            {
                var publicKey = inputFormat switch
                {
                    RSAKeyFormat.PEM => ParsePublicKeyFromPem(pkcs1Key),
                    RSAKeyFormat.Base64 => ParsePublicKeyFromBase64(pkcs1Key, RSAKeyType.PKCS1),
                    RSAKeyFormat.Hex => ParsePublicKeyFromHex(pkcs1Key, RSAKeyType.PKCS1),
                    _ => throw new ArgumentException("不支持的输入格式")
                };
                return GeneratePublicKeyString(publicKey, outputFormat, RSAKeyType.PKCS8);
            }
        }

        /// <summary>
        /// PKCS8转PKCS1格式
        /// </summary>
        /// <param name="pkcs8Key">PKCS8格式密钥</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>PKCS1格式密钥</returns>
        public static string ConvertPkcs8ToPkcs1(string pkcs8Key, bool isPrivateKey, RSAKeyFormat inputFormat = RSAKeyFormat.PEM, RSAKeyFormat outputFormat = RSAKeyFormat.PEM)
        {
            if (isPrivateKey)
            {
                var privateKey = inputFormat switch
                {
                    RSAKeyFormat.PEM => ParsePrivateKeyFromPem(pkcs8Key),
                    RSAKeyFormat.Base64 => ParsePrivateKeyFromBase64(pkcs8Key, RSAKeyType.PKCS8),
                    RSAKeyFormat.Hex => ParsePrivateKeyFromHex(pkcs8Key, RSAKeyType.PKCS8),
                    _ => throw new ArgumentException("不支持的输入格式")
                };
                return GeneratePrivateKeyString(privateKey, outputFormat, RSAKeyType.PKCS1);
            }
            else
            {
                var publicKey = inputFormat switch
                {
                    RSAKeyFormat.PEM => ParsePublicKeyFromPem(pkcs8Key),
                    RSAKeyFormat.Base64 => ParsePublicKeyFromBase64(pkcs8Key, RSAKeyType.PKCS8),
                    RSAKeyFormat.Hex => ParsePublicKeyFromHex(pkcs8Key, RSAKeyType.PKCS8),
                    _ => throw new ArgumentException("不支持的输入格式")
                };
                return GeneratePublicKeyString(publicKey, outputFormat, RSAKeyType.PKCS1);
            }
        }

        /// <summary>
        /// 在不同密钥格式之间进行转换
        /// </summary>
        /// <param name="key">输入的密钥字符串</param>
        /// <param name="isPrivateKey">是否为私钥</param>
        /// <param name="fromFormat">输入密钥的编码格式 (PEM, Base64, Hex)</param>
        /// <param name="fromType">输入密钥的类型 (PKCS1, PKCS8)</param>
        /// <param name="toFormat">输出密钥的编码格式 (PEM, Base64, Hex)</param>
        /// <param name="toType">输出密钥的类型 (PKCS1, PKCS8)</param>
        /// <returns>转换后的密钥字符串</returns>
        public static string ConvertKeyFormat(string key, bool isPrivateKey, RSAKeyFormat fromFormat, RSAKeyType fromType, RSAKeyFormat toFormat, RSAKeyType toType)
        {
            AsymmetricKeyParameter keyParam = ParseKey(key, isPrivateKey, fromFormat, fromType);

            if (isPrivateKey)
            {
                if (keyParam is RsaPrivateCrtKeyParameters privateKey)
                {
                    return GeneratePrivateKeyString(privateKey, toFormat, toType);
                }
                throw new ArgumentException("提供的密钥不是有效的私钥。");
            }
            else
            {
                if (keyParam is RsaKeyParameters publicKey)
                {
                    return GeneratePublicKeyString(publicKey, toFormat, toType);
                }
                throw new ArgumentException("提供的密钥不是有效的公钥。");
            }
        }

        #endregion

        #region 工具方法

        /// <summary>
        /// 获取加密引擎
        /// </summary>
        /// <param name="padding">填充方式</param>
        /// <returns>加密引擎</returns>
        private static IAsymmetricBlockCipher GetCipherEngine(RSAPadding padding)
        {
            var engine = new Org.BouncyCastle.Crypto.Engines.RsaEngine();
            
            return padding switch
            {
                RSAPadding.PKCS1 => new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(engine),
                RSAPadding.OAEP => new Org.BouncyCastle.Crypto.Encodings.OaepEncoding(engine),
                RSAPadding.NoPadding => engine,
                _ => throw new ArgumentException("不支持的填充方式")
            };
        }

        /// <summary>
        /// 获取签名算法名称
        /// </summary>
        /// <param name="algorithm">签名算法</param>
        /// <returns>算法名称</returns>
        private static string GetSignatureAlgorithmName(SignatureAlgorithm algorithm)
        {
            return algorithm switch
            {
                SignatureAlgorithm.SHA1withRSA => "SHA1withRSA",
                SignatureAlgorithm.SHA256withRSA => "SHA256withRSA",
                SignatureAlgorithm.SHA384withRSA => "SHA384withRSA",
                SignatureAlgorithm.SHA512withRSA => "SHA512withRSA",
                SignatureAlgorithm.MD5withRSA => "MD5withRSA",
                _ => throw new ArgumentException($"不支持的签名算法[{algorithm}]")
            };
        }

        /// <summary>
        /// 十六进制字符串转字节数组
        /// </summary>
        /// <param name="hexString">十六进制字符串</param>
        /// <returns>字节数组</returns>
        private static byte[] HexStringToBytes(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("十六进制字符串不能为空");

            hexString = hexString.Replace("-", "").Replace(" ", "");
            if (hexString.Length % 2 != 0)
                throw new ArgumentException("十六进制字符串长度必须为偶数");

            var bytes = new byte[hexString.Length / 2];
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
        /// <returns>十六进制字符串</returns>
        private static string BytesToHexString(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            return BitConverter.ToString(bytes).Replace("-", "");
        }

        #endregion

        #region 向后兼容方法 (为了支持旧代码)

        /// <summary>
        /// RSA类型枚举（用于向后兼容）
        /// </summary>
        public enum RSAType
        {
            RSA = 0,
            RSA2 = 1
        }

        /// <summary>
        /// 创建RSA密钥对（向后兼容）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="format">密钥格式</param>
        /// <returns>公钥和私钥的键值对</returns>
        public static KeyValuePair<string, string> CreateRSAKey(int keySize = 2048, RSAKeyType format = RSAKeyType.PKCS1)
        {
            var keyPair = GenerateKeyPair(keySize);
            var publicKey = (RsaKeyParameters)keyPair.Public;
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            var publicKeyString = GeneratePublicKeyString(publicKey, RSAKeyFormat.PEM, format);
            var privateKeyString = GeneratePrivateKeyString(privateKey, RSAKeyFormat.PEM, format);

            return new KeyValuePair<string, string>(publicKeyString, privateKeyString);
        }

        /// <summary>
        /// RSA加密（向后兼容）
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKeyString">公钥字符串</param>
        /// <param name="format">密钥格式</param>
        /// <returns>Base64格式密文</returns>
        public static string EncryptByRSA(string plaintext, string publicKeyString, RSAKeyType format = RSAKeyType.PKCS1)
        {
            var publicKey = ParsePublicKeyFromPem(publicKeyString);
            return Encrypt(plaintext, publicKey, RSAPadding.PKCS1, RSAKeyFormat.Base64);
        }

        /// <summary>
        /// RSA解密（向后兼容）
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKeyString">私钥字符串</param>
        /// <param name="format">密钥格式</param>
        /// <returns>明文</returns>
        public static string DecryptByRSA(string ciphertext, string privateKeyString, RSAKeyType format = RSAKeyType.PKCS1)
        {
            var privateKey = ParsePrivateKeyFromPem(privateKeyString);
            return Decrypt(ciphertext, privateKey, RSAPadding.PKCS1, RSAKeyFormat.Base64);
        }

        /// <summary>
        /// 哈希并签名字符串（向后兼容）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKeyString">私钥字符串</param>
        /// <param name="rsaType">RSA类型</param>
        /// <param name="format">密钥格式</param>
        /// <returns>签名</returns>
        public static string HashAndSignString(string data, string privateKeyString, RSAType rsaType, RSAKeyType format = RSAKeyType.PKCS1)
        {
            var privateKey = ParsePrivateKeyFromPem(privateKeyString);
            var algorithm = rsaType == RSAType.RSA2 ? SignatureAlgorithm.SHA256withRSA : SignatureAlgorithm.SHA1withRSA;
            return Sign(data, privateKey, algorithm, RSAKeyFormat.Base64);
        }

        /// <summary>
        /// 验证签名（向后兼容）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKeyString">公钥字符串</param>
        /// <param name="rsaType">RSA类型</param>
        /// <param name="format">密钥格式</param>
        /// <returns>验证结果</returns>
        public static bool VerifySigned(string data, string signature, string publicKeyString, RSAType rsaType, RSAKeyType format = RSAKeyType.PKCS1)
        {
            var publicKey = ParsePublicKeyFromPem(publicKeyString);
            var algorithm = rsaType == RSAType.RSA2 ? SignatureAlgorithm.SHA256withRSA : SignatureAlgorithm.SHA1withRSA;
            return Verify(data, signature, publicKey, algorithm, RSAKeyFormat.Base64);
        }

        #endregion
    }
}
