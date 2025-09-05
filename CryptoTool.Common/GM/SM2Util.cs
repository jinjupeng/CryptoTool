using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common.GM
{
    /// <summary>
    /// SM2国密算法工具类，提供SM2非对称加密、签名验签等功能。
    /// SM2是一种基于椭圆曲线密码（ECC）的公钥密码算法，由国家密码管理局发布。
    /// </summary>
    public static class SM2Util
    {
        #region 常量和字段

        /// <summary>
        /// SM2签名算法名称
        /// </summary>
        private const string SM3_WITH_SM2 = "SM3withSM2";

        /// <summary>
        /// 算法名称
        /// </summary>
        private const string ALGORITHM_NAME = "EC";

        /// <summary>
        /// SM2曲线名称
        /// </summary>
        private const string SM2_CURVE_NAME = "SM2P256v1";
        /// <summary>
        ///  65 bytes (uncompressed point for 256-bit curve) 加密过程中生成的随机椭圆曲线点，未压缩格式下长度为65字节
        /// </summary>
        private const int SM2_C1_LENGTH = 65;
        /// <summary>
        /// 32 bytes (SM3 hash) 对明文计算的SM3哈希值，长度为32字节
        /// </summary>
        private const int SM2_C3_LENGTH = 32;
        private const int SM2_RS_LENGTH = 32;

        /// <summary>
        /// SM2密文格式
        /// </summary>
        public enum SM2CipherFormat
        {
            /// <summary>
            /// C1C2C3格式，BouncyCastle默认格式
            /// </summary>
            C1C2C3,
            /// <summary>
            /// C1C3C2格式，国密标准推荐格式
            /// </summary>
            C1C3C2,
            /// <summary>
            /// ASN.1 DER编码格式
            /// </summary>
            ASN1
        }

        /// <summary>
        /// SM2签名格式
        /// </summary>
        public enum SM2SignatureFormat
        {
            /// <summary>
            /// ASN.1 DER编码格式 (BouncyCastle默认)
            /// </summary>
            ASN1,
            /// <summary>
            /// R||S拼接的原始格式
            /// </summary>
            RS
        }

        /// <summary>
        /// 获取SM2曲线参数，这里使用sm2p256v1曲线
        /// </summary>
        private static readonly X9ECParameters SM2_ECX9_PARAMS = GMNamedCurves.GetByName(SM2_CURVE_NAME);

        /// <summary>
        /// 创建ECDomainParameters对象，包含曲线的一些基本参数，如曲线、生成元G、阶N和系数H
        /// </summary>
        private static readonly ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
            SM2_ECX9_PARAMS.Curve,
            SM2_ECX9_PARAMS.G,
            SM2_ECX9_PARAMS.N,
            SM2_ECX9_PARAMS.H);

        #endregion

        #region 密钥对生成

        /// <summary>
        /// 生成SM2密钥对
        /// </summary>
        /// <returns>SM2密钥对</returns>
        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var genParam = new ECKeyGenerationParameters(SM2_DOMAIN_PARAMS, new SecureRandom());
            var generator = new ECKeyPairGenerator();
            generator.Init(genParam);
            return generator.GenerateKeyPair();
        }

        #endregion

        #region 密钥转换（Base64） - 增加原始格式支持

        /// <summary>
        /// 将SM2公钥转换为Base64字符串（SubjectPublicKeyInfo格式，包含完整椭圆曲线参数）
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>Base64编码的公钥</returns>
        /// <exception cref="ArgumentNullException">当公钥为null时抛出</exception>
        public static string PublicKeyToBase64(ECPublicKeyParameters publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            return Convert.ToBase64String(subjectPublicKeyInfo.GetEncoded());
        }

        /// <summary>
        /// 将SM2公钥转换为Base64字符串（原始椭圆曲线点格式，仅包含坐标数据）
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="compressed">是否使用压缩格式</param>
        /// <returns>Base64编码的公钥原始点</returns>
        /// <exception cref="ArgumentNullException">当公钥为null时抛出</exception>
        public static string PublicKeyToRawBase64(ECPublicKeyParameters publicKey, bool compressed = false)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            byte[] rawKeyBytes = publicKey.Q.GetEncoded(compressed);
            return Convert.ToBase64String(rawKeyBytes);
        }

        /// <summary>
        /// 将SM2私钥转换为Base64字符串（PrivateKeyInfo格式，包含完整信息）
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>Base64编码的私钥</returns>
        /// <exception cref="ArgumentNullException">当私钥为null时抛出</exception>
        public static string PrivateKeyToBase64(ECPrivateKeyParameters privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return Convert.ToBase64String(privateKeyInfo.GetEncoded());
        }

        /// <summary>
        /// 将SM2私钥转换为Base64字符串（原始私钥值格式，仅包含私钥数值）
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>Base64编码的私钥原始值</returns>
        /// <exception cref="ArgumentNullException">当私钥为null时抛出</exception>
        public static string PrivateKeyToRawBase64(ECPrivateKeyParameters privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            byte[] rawKeyBytes = privateKey.D.ToByteArrayUnsigned();
            // 确保私钥长度为32字节
            if (rawKeyBytes.Length < 32)
            {
                byte[] paddedKey = new byte[32];
                Buffer.BlockCopy(rawKeyBytes, 0, paddedKey, 32 - rawKeyBytes.Length, rawKeyBytes.Length);
                rawKeyBytes = paddedKey;
            }
            return Convert.ToBase64String(rawKeyBytes);
        }

        /// <summary>
        /// 从Base64字符串解析SM2公钥（支持SubjectPublicKeyInfo格式）
        /// </summary>
        /// <param name="base64PublicKey">Base64编码的公钥</param>
        /// <returns>SM2公钥</returns>
        /// <exception cref="ArgumentNullException">当公钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static ECPublicKeyParameters ParsePublicKeyFromBase64(string base64PublicKey)
        {
            if (string.IsNullOrEmpty(base64PublicKey))
            {
                throw new ArgumentNullException(nameof(base64PublicKey), "Base64格式公钥不能为空");
            }

            try
            {
                byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

                // 尝试作为SubjectPublicKeyInfo格式解析
                try
                {
                    var subjectPublicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyBytes);
                    return (ECPublicKeyParameters)PublicKeyFactory.CreateKey(subjectPublicKeyInfo);
                }
                catch
                {
                    // 如果失败，尝试作为原始椭圆曲线点解析
                    var q = SM2_ECX9_PARAMS.Curve.DecodePoint(publicKeyBytes);
                    return new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
                }
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                throw new FormatException("无效的公钥格式", ex);
            }
        }

        /// <summary>
        /// 从Base64字符串解析SM2私钥（支持PrivateKeyInfo格式和原始私钥值格式）
        /// </summary>
        /// <param name="base64PrivateKey">Base64编码的私钥</param>
        /// <returns>SM2私钥</returns>
        /// <exception cref="ArgumentNullException">当私钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static ECPrivateKeyParameters ParsePrivateKeyFromBase64(string base64PrivateKey)
        {
            if (string.IsNullOrEmpty(base64PrivateKey))
            {
                throw new ArgumentNullException(nameof(base64PrivateKey), "Base64格式私钥不能为空");
            }

            try
            {
                byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey);

                // 尝试作为PrivateKeyInfo格式解析
                try
                {
                    var privateKeyInfo = PrivateKeyInfo.GetInstance(privateKeyBytes);
                    return (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
                }
                catch
                {
                    // 如果失败，尝试作为原始私钥值解析
                    BigInteger d = new BigInteger(1, privateKeyBytes);
                    return new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
                }
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                throw new FormatException("无效的私钥格式", ex);
            }
        }

        #endregion

        #region 密钥转换（Hex）

        /// <summary>
        /// 将公钥转换为16进制字符串
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当公钥为null时抛出</exception>
        public static string PublicKeyToHex(ECPublicKeyParameters publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            byte[] encodedKey = publicKey.Q.GetEncoded(false);
            return Hex.ToHexString(encodedKey).ToUpper();
        }

        /// <summary>
        /// 将私钥转换为16进制字符串
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当私钥为null时抛出</exception>
        public static string PrivateKeyToHex(ECPrivateKeyParameters privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            byte[] d = privateKey.D.ToByteArrayUnsigned();
            return Hex.ToHexString(d).ToUpper();
        }

        /// <summary>
        /// 从16进制字符串解析公钥
        /// </summary>
        /// <param name="hexPublicKey">16进制格式的公钥</param>
        /// <returns>SM2公钥</returns>
        /// <exception cref="ArgumentNullException">当公钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static ECPublicKeyParameters ParsePublicKeyFromHex(string hexPublicKey)
        {
            if (string.IsNullOrEmpty(hexPublicKey))
            {
                throw new ArgumentNullException(nameof(hexPublicKey), "Hex格式公钥不能为空");
            }

            try
            {
                byte[] keyBytes = Hex.Decode(hexPublicKey);
                Org.BouncyCastle.Math.EC.ECPoint point = SM2_ECX9_PARAMS.Curve.DecodePoint(keyBytes);
                return new ECPublicKeyParameters(ALGORITHM_NAME, point, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex)
            {
                throw new FormatException("无效的Hex格式公钥", ex);
            }
        }

        /// <summary>
        /// 从16进制字符串解析私钥
        /// </summary>
        /// <param name="hexPrivateKey">16进制格式的私钥</param>
        /// <returns>SM2私钥</returns>
        /// <exception cref="ArgumentNullException">当私钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static ECPrivateKeyParameters ParsePrivateKeyFromHex(string hexPrivateKey)
        {
            if (string.IsNullOrEmpty(hexPrivateKey))
            {
                throw new ArgumentNullException(nameof(hexPrivateKey), "Hex格式私钥不能为空");
            }

            try
            {
                BigInteger d = new BigInteger(hexPrivateKey, 16);
                return new ECPrivateKeyParameters(ALGORITHM_NAME, d, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex)
            {
                throw new FormatException("无效的Hex格式私钥", ex);
            }
        }

        #endregion

        #region SM2加密解密

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>加密后的数据（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static string Encrypt(byte[] data, ECPublicKeyParameters publicKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待加密数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待加密数据长度不能为0", nameof(data));
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            SM2Engine engine = new SM2Engine();
            ICipherParameters param = new ParametersWithRandom(publicKey, new SecureRandom());
            engine.Init(true, param);
            byte[] encryptedBytes = engine.ProcessBlock(data, 0, data.Length);

            // 根据模式决定输出格式
            switch (format)
            {
                case SM2CipherFormat.C1C3C2:
                    encryptedBytes = C1C2C3ToC1C3C2(encryptedBytes);
                    break;
                case SM2CipherFormat.ASN1:
                    encryptedBytes = C1C2C3ToAsn1(encryptedBytes);
                    break;
                case SM2CipherFormat.C1C2C3:
                default:
                    // BouncyCastle 默认输出 C1C2C3，无需转换
                    break;
            }


            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>加密后的数据（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static string Encrypt(byte[] data, string publicKeyBase64, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待加密数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待加密数据长度不能为0", nameof(data));
            }

            if (string.IsNullOrEmpty(publicKeyBase64))
            {
                throw new ArgumentNullException(nameof(publicKeyBase64), "Base64格式公钥不能为空");
            }

            ECPublicKeyParameters publicKey = ParsePublicKeyFromBase64(publicKeyBase64);
            return Encrypt(data, publicKey, format);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>加密后的字符串（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        public static string Encrypt(string plainText, ECPublicKeyParameters publicKey, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText), "待加密字符串不能为空");
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] data = encoding.GetBytes(plainText);
            return Encrypt(data, publicKey, format);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>加密后的字符串（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static string Encrypt(string plainText, string publicKeyBase64, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText), "待加密字符串不能为空");
            }

            if (string.IsNullOrEmpty(publicKeyBase64))
            {
                throw new ArgumentNullException(nameof(publicKeyBase64), "Base64格式公钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] data = encoding.GetBytes(plainText);
            return Encrypt(data, publicKeyBase64, format);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密数据的Base64编码</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当加密数据格式无效时抛出</exception>
        public static byte[] Decrypt(string encryptedData, ECPrivateKeyParameters privateKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentNullException(nameof(encryptedData), "加密数据不能为空");
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);

                // 根据输入格式，统一转换为BouncyCastle引擎能处理的C1C2C3格式
                switch (format)
                {
                    case SM2CipherFormat.C1C3C2:
                        encryptedBytes = C1C3C2ToC1C2C3(encryptedBytes);
                        break;
                    case SM2CipherFormat.ASN1:
                        encryptedBytes = Asn1ToC1C2C3(encryptedBytes);
                        break;
                    case SM2CipherFormat.C1C2C3:
                    default:
                        // 输入已是 C1C2C3，无需转换
                        break;
                }


                SM2Engine engine = new SM2Engine();
                engine.Init(false, privateKey);
                return engine.ProcessBlock(encryptedBytes, 0, encryptedBytes.Length);
            }
            catch (FormatException ex)
            {
                throw new FormatException("无效的Base64格式加密数据", ex);
            }
            catch (Exception ex)
            {
                throw new CryptographicException("解密失败", ex);
            }
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密数据的Base64编码</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当格式无效时抛出</exception>
        public static byte[] Decrypt(string encryptedData, string privateKeyBase64, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentNullException(nameof(encryptedData), "加密数据不能为空");
            }

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                throw new ArgumentNullException(nameof(privateKeyBase64), "Base64格式私钥不能为空");
            }

            ECPrivateKeyParameters privateKey = ParsePrivateKeyFromBase64(privateKeyBase64);
            return Decrypt(encryptedData, privateKey, format);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密的Base64字符串</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的原文</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当加密数据格式无效时抛出</exception>
        public static string DecryptToString(string encryptedData, ECPrivateKeyParameters privateKey, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentNullException(nameof(encryptedData), "加密数据不能为空");
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] decryptedData = Decrypt(encryptedData, privateKey, format);
            return encoding.GetString(decryptedData);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密的Base64字符串</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的原文</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当格式无效时抛出</exception>
        public static string DecryptToString(string encryptedData, string privateKeyBase64, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentNullException(nameof(encryptedData), "加密数据不能为空");
            }

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                throw new ArgumentNullException(nameof(privateKeyBase64), "Base64格式私钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] decryptedData = Decrypt(encryptedData, privateKeyBase64, format);
            return encoding.GetString(decryptedData);
        }
        #endregion

        #region SM2签名验签

        /// <summary>
        /// 使用SM3WithSM2算法对数据进行签名
        /// </summary>
        /// <param name="data">要签名的数据</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static string SignSm3WithSm2(byte[] data, ECPrivateKeyParameters privateKey, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待签名数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待签名数据长度不能为0", nameof(data));
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            var signer = SignerUtilities.GetSigner(SM3_WITH_SM2);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signature = signer.GenerateSignature(); // BouncyCastle默认生成ASN.1格式

            if (format == SM2SignatureFormat.RS)
            {
                signature = ConvertAsn1ToRs(signature);
            }

            return Hex.ToHexString(signature).ToUpper();
        }

        /// <summary>
        /// 使用SM3WithSM2算法对字符串数据进行签名
        /// </summary>
        /// <param name="data">要签名的字符串</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        public static string SignSm3WithSm2(string data, ECPrivateKeyParameters privateKey, Encoding encoding = null, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException(nameof(data), "待签名字符串不能为空");
            }

            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return SignSm3WithSm2(dataBytes, privateKey, format);
        }

        /// <summary>
        /// 使用SM3WithSM2算法对数据进行签名
        /// </summary>
        /// <param name="data">要签名的数据</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static string SignSm3WithSm2(byte[] data, string privateKeyBase64, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待签名数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待签名数据长度不能为0", nameof(data));
            }

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                throw new ArgumentNullException(nameof(privateKeyBase64), "Base64格式私钥不能为空");
            }

            ECPrivateKeyParameters privateKey = ParsePrivateKeyFromBase64(privateKeyBase64);
            return SignSm3WithSm2(data, privateKey, format);
        }

        /// <summary>
        /// 使用SM3WithSM2算法对字符串数据进行签名
        /// </summary>
        /// <param name="data">要签名的字符串</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static string SignSm3WithSm2(string data, string privateKeyBase64, Encoding encoding = null, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException(nameof(data), "待签名字符串不能为空");
            }

            if (string.IsNullOrEmpty(privateKeyBase64))
            {
                throw new ArgumentNullException(nameof(privateKeyBase64), "Base64格式私钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return SignSm3WithSm2(dataBytes, privateKeyBase64, format);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0或字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(byte[] data, string signature, ECPublicKeyParameters publicKey, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待验证数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待验证数据长度不能为0", nameof(data));
            }

            if (string.IsNullOrEmpty(signature))
            {
                throw new ArgumentNullException(nameof(signature), "签名不能为空");
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            try
            {
                byte[] signBytes = Hex.Decode(signature);

                if (format == SM2SignatureFormat.RS)
                {
                    signBytes = ConvertRsToAsn1(signBytes);
                }

                var signer = SignerUtilities.GetSigner(SM3_WITH_SM2);
                signer.Init(false, publicKey);
                signer.BlockUpdate(data, 0, data.Length);
                return signer.VerifySignature(signBytes);
            }
            catch (Exception ex)
            {
                throw new FormatException("无效的签名格式", ex);
            }
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始字符串</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(string data, string signature, ECPublicKeyParameters publicKey, Encoding encoding = null, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException(nameof(data), "待验证字符串不能为空");
            }

            if (string.IsNullOrEmpty(signature))
            {
                throw new ArgumentNullException(nameof(signature), "签名不能为空");
            }

            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return VerifySm3WithSm2(dataBytes, signature, publicKey, format);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0或字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名或公钥格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(byte[] data, string signature, string publicKeyBase64, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "待验证数据不能为空");
            }

            if (data.Length == 0)
            {
                throw new ArgumentException("待验证数据长度不能为0", nameof(data));
            }

            if (string.IsNullOrEmpty(signature))
            {
                throw new ArgumentNullException(nameof(signature), "签名不能为空");
            }

            if (string.IsNullOrEmpty(publicKeyBase64))
            {
                throw new ArgumentNullException(nameof(publicKeyBase64), "Base64格式公钥不能为空");
            }

            ECPublicKeyParameters publicKey = ParsePublicKeyFromBase64(publicKeyBase64);
            return VerifySm3WithSm2(data, signature, publicKey, format);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始字符串</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名或公钥格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(string data, string signature, string publicKeyBase64, Encoding encoding = null, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (string.IsNullOrEmpty(data))
            {
                throw new ArgumentNullException(nameof(data), "待验证字符串不能为空");
            }

            if (string.IsNullOrEmpty(signature))
            {
                throw new ArgumentNullException(nameof(signature), "签名不能为空");
            }

            if (string.IsNullOrEmpty(publicKeyBase64))
            {
                throw new ArgumentNullException(nameof(publicKeyBase64), "Base64格式公钥不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return VerifySm3WithSm2(dataBytes, signature, publicKeyBase64, format);
        }

        #endregion

        #region 密文格式转换 (C1C2C3 <-> C1C3C2 <-> ASN.1)

        /// <summary>
        /// 将BouncyCastle的C1C2C3密文格式转换为C1C3C2格式。
        /// SM2标准推荐的密文顺序是C1C3C2，而BouncyCastle默认输出为C1C2C3。
        /// </summary>
        /// <param name="c1c2c3">C1C2C3格式的密文。</param>
        /// <returns>C1C3C2格式的密文。</returns>
        /// <exception cref="ArgumentException">当密文格式无效时抛出。</exception>
        public static byte[] C1C2C3ToC1C3C2(byte[] c1c2c3)
        {
            if (c1c2c3 == null || c1c2c3.Length <= SM2_C1_LENGTH + SM2_C3_LENGTH)
            {
                throw new ArgumentException("无效的C1C2C3格式密文", nameof(c1c2c3));
            }

            // C2: variable length 实际的密文数据，长度与明文长度相同
            int c2Length = c1c2c3.Length - SM2_C1_LENGTH - SM2_C3_LENGTH;

            byte[] c1 = new byte[SM2_C1_LENGTH];
            Buffer.BlockCopy(c1c2c3, 0, c1, 0, SM2_C1_LENGTH);

            byte[] c2 = new byte[c2Length];
            Buffer.BlockCopy(c1c2c3, SM2_C1_LENGTH, c2, 0, c2Length);

            byte[] c3 = new byte[SM2_C3_LENGTH];
            Buffer.BlockCopy(c1c2c3, SM2_C1_LENGTH + c2Length, c3, 0, SM2_C3_LENGTH);

            byte[] c1c3c2 = new byte[c1c2c3.Length];
            Buffer.BlockCopy(c1, 0, c1c3c2, 0, SM2_C1_LENGTH);
            Buffer.BlockCopy(c3, 0, c1c3c2, SM2_C1_LENGTH, SM2_C3_LENGTH);
            Buffer.BlockCopy(c2, 0, c1c3c2, SM2_C1_LENGTH + SM2_C3_LENGTH, c2Length);

            return c1c3c2;
        }

        /// <summary>
        /// 将C1C3C2密文格式转换为BouncyCastle兼容的C1C2C3格式。
        /// </summary>
        /// <param name="c1c3c2">C1C3C2格式的密文。</param>
        /// <returns>C1C2C3格式的密文。</returns>
        /// <exception cref="ArgumentException">当密文格式无效时抛出。</exception>
        public static byte[] C1C3C2ToC1C2C3(byte[] c1c3c2)
        {
            if (c1c3c2 == null || c1c3c2.Length <= SM2_C1_LENGTH + SM2_C3_LENGTH)
            {
                throw new ArgumentException("无效的C1C3C2格式密文", nameof(c1c3c2));
            }

            //C2: variable length 实际的密文数据，长度与明文长度相同
            int c2Length = c1c3c2.Length - SM2_C1_LENGTH - SM2_C3_LENGTH;

            byte[] c1 = new byte[SM2_C1_LENGTH];
            Buffer.BlockCopy(c1c3c2, 0, c1, 0, SM2_C1_LENGTH);

            byte[] c3 = new byte[SM2_C3_LENGTH];
            Buffer.BlockCopy(c1c3c2, SM2_C1_LENGTH, c3, 0, SM2_C3_LENGTH);

            byte[] c2 = new byte[c2Length];
            Buffer.BlockCopy(c1c3c2, SM2_C1_LENGTH + SM2_C3_LENGTH, c2, 0, c2Length);

            byte[] c1c2c3 = new byte[c1c3c2.Length];
            Buffer.BlockCopy(c1, 0, c1c2c3, 0, SM2_C1_LENGTH);
            Buffer.BlockCopy(c2, 0, c1c2c3, SM2_C1_LENGTH, c2Length);
            Buffer.BlockCopy(c3, 0, c1c2c3, SM2_C1_LENGTH + c2Length, SM2_C3_LENGTH);

            return c1c2c3;
        }

        /// <summary>
        /// 将BouncyCastle的C1C2C3密文格式转换为ASN.1 DER编码格式。
        /// </summary>
        /// <param name="c1c2c3">C1C2C3格式的密文。</param>
        /// <returns>ASN.1 DER编码的密文。</returns>
        public static byte[] C1C2C3ToAsn1(byte[] c1c2c3)
        {
            // C1C2C3 = C1 || C2 || C3
            // C1 = 04 || X || Y
            // ASN.1 = SEQ(X, Y, C3, C2)
            int c2Length = c1c2c3.Length - SM2_C1_LENGTH - SM2_C3_LENGTH;

            byte[] c1x = new byte[SM2_RS_LENGTH];
            Buffer.BlockCopy(c1c2c3, 1, c1x, 0, SM2_RS_LENGTH);

            byte[] c1y = new byte[SM2_RS_LENGTH];
            Buffer.BlockCopy(c1c2c3, 1 + SM2_RS_LENGTH, c1y, 0, SM2_RS_LENGTH);

            byte[] c2 = new byte[c2Length];
            Buffer.BlockCopy(c1c2c3, SM2_C1_LENGTH, c2, 0, c2Length);

            byte[] c3 = new byte[SM2_C3_LENGTH];
            Buffer.BlockCopy(c1c2c3, SM2_C1_LENGTH + c2Length, c3, 0, SM2_C3_LENGTH);

            Asn1EncodableVector vector = new Asn1EncodableVector
            {
                new DerInteger(new BigInteger(1, c1x)),
                new DerInteger(new BigInteger(1, c1y)),
                new DerOctetString(c3),
                new DerOctetString(c2)
            };

            return new DerSequence(vector).GetEncoded("DER");
        }

        /// <summary>
        /// 将ASN.1 DER编码的密文转换为BouncyCastle兼容的C1C2C3格式。
        /// </summary>
        /// <param name="asn1">ASN.1 DER编码的密文。</param>
        /// <returns>C1C2C3格式的密文。</returns>
        public static byte[] Asn1ToC1C2C3(byte[] asn1)
        {
            Asn1Sequence sequence = Asn1Sequence.GetInstance(asn1);
            BigInteger x = ((DerInteger)sequence[0]).Value;
            BigInteger y = ((DerInteger)sequence[1]).Value;
            byte[] c3 = ((Asn1OctetString)sequence[2]).GetOctets();
            byte[] c2 = ((Asn1OctetString)sequence[3]).GetOctets();

            Org.BouncyCastle.Math.EC.ECPoint c1Point = SM2_ECX9_PARAMS.Curve.CreatePoint(x, y);
            byte[] c1 = c1Point.GetEncoded(false);

            return Arrays.ConcatenateAll(c1, c2, c3);
        }

        #endregion

        #region 签名格式转换 (RS <-> ASN.1 DER)

        /// <summary>
        /// 将R||S格式的签名转换为ASN.1 DER编码格式。
        /// </summary>
        /// <param name="rs">R和S拼接的字节数组。</param>
        /// <returns>ASN.1 DER编码的签名。</returns>
        /// <exception cref="ArgumentException">当RS格式签名无效时抛出</exception>
        public static byte[] ConvertRsToAsn1(byte[] rs)
        {
            if (rs == null || rs.Length != SM2_RS_LENGTH * 2)
            {
                throw new ArgumentException("无效的RS格式签名", nameof(rs));
            }

            BigInteger r = new BigInteger(1, Arrays.CopyOfRange(rs, 0, SM2_RS_LENGTH));
            BigInteger s = new BigInteger(1, Arrays.CopyOfRange(rs, SM2_RS_LENGTH, SM2_RS_LENGTH * 2));

            Asn1EncodableVector vector = new Asn1EncodableVector
            {
                new DerInteger(r),
                new DerInteger(s)
            };

            return new DerSequence(vector).GetEncoded("DER");
        }

        /// <summary>
        /// 将ASN.1 DER编码的签名转换为R||S格式。
        /// </summary>
        /// <param name="asn1">ASN.1 DER编码的签名。</param>
        /// <returns>R和S拼接的字节数组。</returns>
        /// <exception cref="ArgumentException">当ASN.1格式签名无效时抛出</exception>
        public static byte[] ConvertAsn1ToRs(byte[] asn1)
        {
            if (asn1 == null || asn1.Length == 0)
            {
                throw new ArgumentException("ASN.1格式签名不能为空", nameof(asn1));
            }

            try
            {
                Asn1Sequence sequence = Asn1Sequence.GetInstance(asn1);
                if (sequence.Count != 2)
                {
                    throw new ArgumentException("ASN.1签名格式错误：应包含两个元素（R和S）");
                }

                byte[] r = ConvertBigIntegerToFixedLengthByteArray(((DerInteger)sequence[0]).Value);
                byte[] s = ConvertBigIntegerToFixedLengthByteArray(((DerInteger)sequence[1]).Value);

                return Arrays.Concatenate(r, s);
            }
            catch (Exception ex) when (!(ex is ArgumentException))
            {
                throw new ArgumentException("无效的ASN.1格式签名", nameof(asn1), ex);
            }
        }

        /// <summary>
        /// 将BigInteger转换为固定长度的字节数组（32字节）。
        /// 确保与Java的BigInteger.toByteArray()行为兼容。
        /// </summary>
        /// <param name="bigInt">要转换的BigInteger</param>
        /// <returns>32字节的字节数组</returns>
        /// <exception cref="ArgumentException">当BigInteger无法转换为32字节数组时抛出</exception>
        private static byte[] ConvertBigIntegerToFixedLengthByteArray(BigInteger bigInt)
        {
            if (bigInt == null)
            {
                throw new ArgumentException("BigInteger不能为null");
            }

            // 对于SM2P256v1，R和S的长度应为32字节
            byte[] rs = bigInt.ToByteArrayUnsigned();

            // 如果长度正好是32字节，直接返回
            if (rs.Length == SM2_RS_LENGTH)
            {
                return rs;
            }
            // 如果长度小于32字节，则在前面补0
            else if (rs.Length < SM2_RS_LENGTH)
            {
                byte[] result = new byte[SM2_RS_LENGTH];
                Buffer.BlockCopy(rs, 0, result, SM2_RS_LENGTH - rs.Length, rs.Length);
                return result;
            }
            // 如果长度是33字节且第一个字节是0（Java BigInteger的符号位），则移除符号位
            else if (rs.Length == SM2_RS_LENGTH + 1 && rs[0] == 0)
            {
                return Arrays.CopyOfRange(rs, 1, SM2_RS_LENGTH + 1);
            }
            // 其他异常情况
            else
            {
                throw new ArgumentException($"BigInteger转换为固定长度字节数组时发生意外长度: {rs.Length}。预期长度: {SM2_RS_LENGTH}", nameof(bigInt));
            }
        }

        /// <summary>
        /// 将16进制字符串格式的RS签名转换为ASN.1 DER格式。
        /// </summary>
        /// <param name="hexRs">16进制格式的RS签名字符串</param>
        /// <returns>ASN.1 DER格式的签名（16进制字符串）</returns>
        /// <exception cref="ArgumentException">当输入格式无效时抛出</exception>
        public static string ConvertHexRsToHexAsn1(string hexRs)
        {
            if (string.IsNullOrEmpty(hexRs))
            {
                throw new ArgumentException("Hex格式RS签名不能为空", nameof(hexRs));
            }

            if (hexRs.Length != SM2_RS_LENGTH * 2 * 2) // 每字节2个16进制字符，R和S各32字节
            {
                throw new ArgumentException($"Hex格式RS签名长度错误。预期长度: {SM2_RS_LENGTH * 2 * 2}，实际长度: {hexRs.Length}", nameof(hexRs));
            }

            try
            {
                byte[] rsBytes = Hex.Decode(hexRs);
                byte[] asn1Bytes = ConvertRsToAsn1(rsBytes);
                return Hex.ToHexString(asn1Bytes).ToUpper();
            }
            catch (Exception ex)
            {
                throw new ArgumentException("转换Hex格式RS签名到ASN.1失败", nameof(hexRs), ex);
            }
        }

        /// <summary>
        /// 将16进制字符串格式的ASN.1 DER签名转换为RS格式。
        /// </summary>
        /// <param name="hexAsn1">16进制格式的ASN.1 DER签名字符串</param>
        /// <returns>RS格式的签名（16进制字符串）</returns>
        /// <exception cref="ArgumentException">当输入格式无效时抛出</exception>
        public static string ConvertHexAsn1ToHexRs(string hexAsn1)
        {
            if (string.IsNullOrEmpty(hexAsn1))
            {
                throw new ArgumentException("Hex格式ASN.1签名不能为空", nameof(hexAsn1));
            }

            try
            {
                byte[] asn1Bytes = Hex.Decode(hexAsn1);
                byte[] rsBytes = ConvertAsn1ToRs(asn1Bytes);
                return Hex.ToHexString(rsBytes).ToUpper();
            }
            catch (Exception ex)
            {
                throw new ArgumentException("转换Hex格式ASN.1签名到RS失败", nameof(hexAsn1), ex);
            }
        }

        /// <summary>
        /// 验证RS格式签名是否有效。
        /// </summary>
        /// <param name="rsBytes">RS格式的签名字节数组</param>
        /// <returns>如果格式有效返回true，否则返回false</returns>
        public static bool IsValidRsSignature(byte[] rsBytes)
        {
            if (rsBytes == null || rsBytes.Length != SM2_RS_LENGTH * 2)
            {
                return false;
            }

            try
            {
                // 验证R和S都不为0
                BigInteger r = new BigInteger(1, Arrays.CopyOfRange(rsBytes, 0, SM2_RS_LENGTH));
                BigInteger s = new BigInteger(1, Arrays.CopyOfRange(rsBytes, SM2_RS_LENGTH, SM2_RS_LENGTH * 2));

                return !r.Equals(BigInteger.Zero) && !s.Equals(BigInteger.Zero);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 验证ASN.1 DER格式签名是否有效。
        /// </summary>
        /// <param name="asn1Bytes">ASN.1 DER格式的签名字节数组</param>
        /// <returns>如果格式有效返回true，否则返回false</returns>
        public static bool IsValidAsn1Signature(byte[] asn1Bytes)
        {
            if (asn1Bytes == null || asn1Bytes.Length == 0)
            {
                return false;
            }

            try
            {
                Asn1Sequence sequence = Asn1Sequence.GetInstance(asn1Bytes);
                if (sequence.Count != 2)
                {
                    return false;
                }

                BigInteger r = ((DerInteger)sequence[0]).Value;
                BigInteger s = ((DerInteger)sequence[1]).Value;

                return !r.Equals(BigInteger.Zero) && !s.Equals(BigInteger.Zero);
            }
            catch
            {
                return false;
            }
        }

        #endregion

        #region Java兼容性处理

        /// <summary>
        /// 将.NET BouncyCastle生成的密文转换为Java BouncyCastle兼容格式
        /// (.NET密文需要移除开头的0x04字节才能在Java中解密)
        /// </summary>
        /// <param name="dotNetCiphertext">来自.NET BouncyCastle的密文</param>
        /// <returns>Java BouncyCastle兼容的密文</returns>
        public static byte[] ConvertDotNetCiphertextToJava(byte[] dotNetCiphertext)
        {
            if (dotNetCiphertext == null || dotNetCiphertext.Length <= SM2_C1_LENGTH + SM2_C3_LENGTH)
            {
                throw new ArgumentException("无效的.NET密文格式", nameof(dotNetCiphertext));
            }

            // .NET BouncyCastle的C1部分包含0x04前缀（未压缩点标识）
            // Java BouncyCastle期望不包含此前缀
            if (dotNetCiphertext[0] != 0x04)
            {
                throw new ArgumentException("密文格式错误：期望以0x04开头", nameof(dotNetCiphertext));
            }

            // 移除0x04前缀，创建Java兼容的密文
            byte[] javaCiphertext = new byte[dotNetCiphertext.Length - 1];
            Buffer.BlockCopy(dotNetCiphertext, 1, javaCiphertext, 0, dotNetCiphertext.Length - 1);

            return javaCiphertext;
        }

        /// <summary>
        /// 将Java BouncyCastle生成的密文转换为.NET BouncyCastle兼容格式
        /// (Java密文需要在开头添加0x04字节才能在.NET中解密)
        /// </summary>
        /// <param name="javaCiphertext">来自Java BouncyCastle的密文</param>
        /// <returns>.NET BouncyCastle兼容的密文</returns>
        public static byte[] ConvertJavaCiphertextToDotNet(byte[] javaCiphertext)
        {
            if (javaCiphertext == null || javaCiphertext.Length <= (SM2_C1_LENGTH - 1) + SM2_C3_LENGTH)
            {
                throw new ArgumentException("无效的Java密文格式", nameof(javaCiphertext));
            }

            // Java BouncyCastle的C1部分不包含0x04前缀
            // .NET BouncyCastle期望包含此前缀（未压缩点标识）
            byte[] dotNetCiphertext = new byte[javaCiphertext.Length + 1];
            dotNetCiphertext[0] = 0x04; // 添加未压缩点标识
            Buffer.BlockCopy(javaCiphertext, 0, dotNetCiphertext, 1, javaCiphertext.Length);

            return dotNetCiphertext;
        }

        /// <summary>
        /// 使用Java兼容模式加密数据
        /// (生成的密文可以直接在Java端解密，无需额外转换)
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>Java兼容的加密数据（Base64编码）</returns>
        public static string EncryptForJava(byte[] data, ECPublicKeyParameters publicKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            // 先用标准方式加密
            string dotNetCiphertext = Encrypt(data, publicKey, format);
            byte[] dotNetBytes = Convert.FromBase64String(dotNetCiphertext);

            // 根据格式进行相应的Java兼容性转换
            byte[] javaCompatibleBytes;
            switch (format)
            {
                case SM2CipherFormat.C1C2C3:
                case SM2CipherFormat.C1C3C2:
                    // 对于C1C2C3和C1C3C2格式，需要移除0x04前缀
                    javaCompatibleBytes = ConvertDotNetCiphertextToJava(dotNetBytes);
                    break;
                case SM2CipherFormat.ASN1:
                    // ASN.1格式通常不需要此转换，因为坐标已经编码在ASN.1结构中
                    javaCompatibleBytes = dotNetBytes;
                    break;
                default:
                    javaCompatibleBytes = dotNetBytes;
                    break;
            }

            return Convert.ToBase64String(javaCompatibleBytes);
        }

        /// <summary>
        /// 使用Java兼容模式加密字符串
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>Java兼容的加密字符串（Base64编码）</returns>
        public static string EncryptForJava(string plainText, ECPublicKeyParameters publicKey, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText), "待加密字符串不能为空");
            }

            encoding = encoding ?? Encoding.UTF8;
            byte[] data = encoding.GetBytes(plainText);
            return EncryptForJava(data, publicKey, format);
        }

        /// <summary>
        /// 解密来自Java的密文数据
        /// (自动处理Java密文格式，添加必要的0x04前缀)
        /// </summary>
        /// <param name="encryptedData">来自Java的加密数据（Base64编码）</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的数据</returns>
        public static byte[] DecryptFromJava(string encryptedData, ECPrivateKeyParameters privateKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentNullException(nameof(encryptedData), "加密数据不能为空");
            }

            byte[] javaCiphertext = Convert.FromBase64String(encryptedData);

            // 根据格式进行相应的.NET兼容性转换
            byte[] dotNetCompatibleBytes;
            switch (format)
            {
                case SM2CipherFormat.C1C2C3:
                case SM2CipherFormat.C1C3C2:
                    // 对于C1C2C3和C1C3C2格式，需要添加0x04前缀
                    dotNetCompatibleBytes = ConvertJavaCiphertextToDotNet(javaCiphertext);
                    break;
                case SM2CipherFormat.ASN1:
                    // ASN.1格式通常不需要此转换
                    dotNetCompatibleBytes = javaCiphertext;
                    break;
                default:
                    dotNetCompatibleBytes = javaCiphertext;
                    break;
            }

            string dotNetCiphertext = Convert.ToBase64String(dotNetCompatibleBytes);
            return Decrypt(dotNetCiphertext, privateKey, format);
        }

        /// <summary>
        /// 解密来自Java的密文为字符串
        /// </summary>
        /// <param name="encryptedData">来自Java的加密数据（Base64编码）</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的字符串</returns>
        public static string DecryptFromJavaToString(string encryptedData, ECPrivateKeyParameters privateKey, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] decryptedData = DecryptFromJava(encryptedData, privateKey, format);
            return encoding.GetString(decryptedData);
        }

        /// <summary>
        /// 检测密文是否为Java格式（不包含0x04前缀）
        /// </summary>
        /// <param name="ciphertext">密文字节数组</param>
        /// <param name="format">密文格式</param>
        /// <returns>如果是Java格式返回true，否则返回false</returns>
        public static bool IsJavaFormat(byte[] ciphertext, SM2CipherFormat format)
        {
            if (ciphertext == null || ciphertext.Length == 0)
            {
                return false;
            }

            switch (format)
            {
                case SM2CipherFormat.C1C2C3:
                case SM2CipherFormat.C1C3C2:
                    // Java格式的密文不以0x04开头，且长度比.NET格式少1字节
                    return ciphertext[0] != 0x04 && ciphertext.Length >= (SM2_C1_LENGTH - 1) + SM2_C3_LENGTH;
                case SM2CipherFormat.ASN1:
                    // ASN.1格式通过ASN.1结构判断
                    try
                    {
                        Asn1Sequence.GetInstance(ciphertext);
                        return true;
                    }
                    catch
                    {
                        return false;
                    }
                default:
                    return false;
            }
        }

        /// <summary>
        /// 智能解密方法 - 自动检测密文来源并使用相应的解密方式
        /// </summary>
        /// <param name="encryptedData">加密数据（Base64编码）</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的数据</returns>
        public static byte[] SmartDecrypt(string encryptedData, ECPrivateKeyParameters privateKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            byte[] ciphertext = Convert.FromBase64String(encryptedData);

            if (IsJavaFormat(ciphertext, format))
            {
                Console.WriteLine("检测到Java格式密文，使用Java兼容解密模式");
                return DecryptFromJava(encryptedData, privateKey, format);
            }
            else
            {
                Console.WriteLine("检测到.NET格式密文，使用标准解密模式");
                return Decrypt(encryptedData, privateKey, format);
            }
        }

        /// <summary>
        /// 智能解密方法 - 返回字符串
        /// </summary>
        /// <param name="encryptedData">加密数据（Base64编码）</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的字符串</returns>
        public static string SmartDecryptToString(string encryptedData, ECPrivateKeyParameters privateKey, Encoding encoding = null, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] decryptedData = SmartDecrypt(encryptedData, privateKey, format);
            return encoding.GetString(decryptedData);
        }

        #endregion
    }
}
