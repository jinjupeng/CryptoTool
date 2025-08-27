using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
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

        #region 密钥转换（Base64）

        /// <summary>
        /// 将SM2公钥转换为Base64字符串
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
        /// 将SM2私钥转换为Base64字符串
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
        /// 从Base64字符串解析SM2公钥
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
                // 将Base64格式的公钥字符串转换为字节数组
                byte[] publicKeyBytes = Convert.FromBase64String(base64PublicKey);

                // 使用曲线参数解码公钥字节数组，将其转换为ECPoint
                var q = SM2_ECX9_PARAMS.Curve.DecodePoint(publicKeyBytes);

                // 根据解码后的ECPoint和ECDomainParameters创建ECPublicKeyParameters对象
                return new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                throw new FormatException("无效的公钥格式", ex);
            }
        }

        /// <summary>
        /// 从Base64编码的原始椭圆曲线点创建SM2公钥
        /// </summary>
        /// <param name="base64Key">Base64编码的原始公钥点</param>
        /// <returns>SM2公钥参数</returns>
        /// <exception cref="ArgumentNullException">当公钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static ECPublicKeyParameters ParseRawPublicKeyFromBase64(string base64Key)
        {
            if (string.IsNullOrEmpty(base64Key))
            {
                throw new ArgumentNullException(nameof(base64Key), "Base64格式公钥点不能为空");
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(base64Key);
                Org.BouncyCastle.Math.EC.ECPoint point = SM2_ECX9_PARAMS.Curve.DecodePoint(keyBytes);
                return new ECPublicKeyParameters(ALGORITHM_NAME, point, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                throw new FormatException("无效的公钥格式", ex);
            }
        }

        /// <summary>
        /// 从Base64编码的原始私钥值创建SM2私钥
        /// </summary>
        /// <param name="base64Key">Base64编码的原始私钥值</param>
        /// <returns>SM2私钥参数</returns>
        /// <exception cref="ArgumentNullException">当私钥字符串为null或空时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static ECPrivateKeyParameters ParseRawPrivateKeyFromBase64(string base64Key)
        {
            if (string.IsNullOrEmpty(base64Key))
            {
                throw new ArgumentNullException(nameof(base64Key), "Base64格式私钥值不能为空");
            }

            try
            {
                byte[] keyBytes = Convert.FromBase64String(base64Key);
                BigInteger d = new BigInteger(1, keyBytes);
                return new ECPrivateKeyParameters(ALGORITHM_NAME, d, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex) when (ex is FormatException || ex is ArgumentException)
            {
                throw new FormatException("无效的私钥格式", ex);
            }
        }

        /// <summary>
        /// 从Base64字符串解析SM2私钥
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
                // 将Base64格式的私钥字符串转换为字节数组
                byte[] privateKeyBytes = Convert.FromBase64String(base64PrivateKey);

                // 使用BigInteger构造函数将字节数组转换为无符号大整数，这将表示我们的私钥
                BigInteger d = new BigInteger(1, privateKeyBytes);

                // 根据无符号大整数和ECDomainParameters创建ECPrivateKeyParameters对象，表示私钥
                return new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
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
        /// <returns>加密后的数据（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static string Encrypt(byte[] data, ECPublicKeyParameters publicKey)
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
            byte[] encrypted = engine.ProcessBlock(data, 0, data.Length);
            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <returns>加密后的数据（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static string Encrypt(byte[] data, string publicKeyBase64)
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
            return Encrypt(data, publicKey);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>加密后的字符串（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        public static string Encrypt(string plainText, ECPublicKeyParameters publicKey, Encoding encoding = null)
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
            return Encrypt(data, publicKey);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>加密后的字符串（Base64编码）</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当公钥格式无效时抛出</exception>
        public static string Encrypt(string plainText, string publicKeyBase64, Encoding encoding = null)
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
            return Encrypt(data, publicKeyBase64);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密数据的Base64编码</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当加密数据格式无效时抛出</exception>
        public static byte[] Decrypt(string encryptedData, ECPrivateKeyParameters privateKey)
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
                byte[] data = Convert.FromBase64String(encryptedData);
                SM2Engine engine = new SM2Engine();
                engine.Init(false, privateKey);
                return engine.ProcessBlock(data, 0, data.Length);
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
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当格式无效时抛出</exception>
        public static byte[] Decrypt(string encryptedData, string privateKeyBase64)
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
            return Decrypt(encryptedData, privateKey);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密的Base64字符串</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>解密后的原文</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当加密数据格式无效时抛出</exception>
        public static string DecryptToString(string encryptedData, ECPrivateKeyParameters privateKey, Encoding encoding = null)
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
            byte[] decryptedData = Decrypt(encryptedData, privateKey);
            return encoding.GetString(decryptedData);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密的Base64字符串</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>解密后的原文</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当格式无效时抛出</exception>
        public static string DecryptToString(string encryptedData, string privateKeyBase64, Encoding encoding = null)
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
            byte[] decryptedData = Decrypt(encryptedData, privateKeyBase64);
            return encoding.GetString(decryptedData);
        }

        #endregion

        #region SM2签名验签

        /// <summary>
        /// 使用SM3WithSM2算法对数据进行签名
        /// </summary>
        /// <param name="data">要签名的数据</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static string SignSm3WithSm2(byte[] data, ECPrivateKeyParameters privateKey)
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
            byte[] signature = signer.GenerateSignature();
            return Hex.ToHexString(signature).ToUpper();
        }

        /// <summary>
        /// 使用SM3WithSM2算法对字符串数据进行签名
        /// </summary>
        /// <param name="data">要签名的字符串</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        public static string SignSm3WithSm2(string data, ECPrivateKeyParameters privateKey, Encoding encoding = null)
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
            return SignSm3WithSm2(dataBytes, privateKey);
        }

        /// <summary>
        /// 使用SM3WithSM2算法对数据进行签名
        /// </summary>
        /// <param name="data">要签名的数据</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static string SignSm3WithSm2(byte[] data, string privateKeyBase64)
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
            return SignSm3WithSm2(data, privateKey);
        }

        /// <summary>
        /// 使用SM3WithSM2算法对字符串数据进行签名
        /// </summary>
        /// <param name="data">要签名的字符串</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>签名结果的16进制字符串</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当私钥格式无效时抛出</exception>
        public static string SignSm3WithSm2(string data, string privateKeyBase64, Encoding encoding = null)
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
            return SignSm3WithSm2(dataBytes, privateKeyBase64);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0或字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(byte[] data, string signature, ECPublicKeyParameters publicKey)
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
                var signer = SignerUtilities.GetSigner(SM3_WITH_SM2);
                signer.Init(false, publicKey);
                signer.BlockUpdate(data, 0, data.Length);
                byte[] signBytes = Hex.Decode(signature);
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
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(string data, string signature, ECPublicKeyParameters publicKey, Encoding encoding = null)
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
            return VerifySm3WithSm2(dataBytes, signature, publicKey);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0或字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名或公钥格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(byte[] data, string signature, string publicKeyBase64)
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
            return VerifySm3WithSm2(data, signature, publicKey);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始字符串</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKeyBase64">SM2公钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当字符串为空时抛出</exception>
        /// <exception cref="FormatException">当签名或公钥格式无效时抛出</exception>
        public static bool VerifySm3WithSm2(string data, string signature, string publicKeyBase64, Encoding encoding = null)
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
            return VerifySm3WithSm2(dataBytes, signature, publicKeyBase64);
        }

        #endregion
    }
}
