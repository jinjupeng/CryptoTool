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
using System.Text;

namespace CryptoTool.Common.GM
{
    /// <summary>
    /// SM2 算法工具类。
    /// </summary>
    public static class SM2Util
    {
        private static readonly X9ECParameters SM2_ECX9_PARAMS = GMNamedCurves.GetByName("SM2P256v1");
        private static readonly ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(SM2_ECX9_PARAMS.Curve, SM2_ECX9_PARAMS.G, SM2_ECX9_PARAMS.N);

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

        /// <summary>
        /// 将SM2公钥转换为Base64字符串
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>Base64编码的公钥</returns>
        public static string PublicKeyToBase64(ECPublicKeyParameters publicKey)
        {
            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            return Convert.ToBase64String(subjectPublicKeyInfo.GetEncoded());
        }

        /// <summary>
        /// 将SM2私钥转换为Base64字符串
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>Base64编码的私钥</returns>
        public static string PrivateKeyToBase64(ECPrivateKeyParameters privateKey)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return Convert.ToBase64String(privateKeyInfo.GetEncoded());
        }

        /// <summary>
        /// 从Base64字符串解析SM2公钥
        /// </summary>
        /// <param name="base64Key">Base64编码的公钥</param>
        /// <returns>SM2公钥</returns>
        public static ECPublicKeyParameters ParsePublicKeyFromBase64(string base64Key)
        {
            byte[] keyBytes = Convert.FromBase64String(base64Key);
            AsymmetricKeyParameter publicKey = PublicKeyFactory.CreateKey(keyBytes);
            return (ECPublicKeyParameters)publicKey;
        }

        /// <summary>
        /// 从Base64字符串解析SM2私钥
        /// </summary>
        /// <param name="base64Key">Base64编码的私钥</param>
        /// <returns>SM2私钥</returns>
        public static ECPrivateKeyParameters ParsePrivateKeyFromBase64(string base64Key)
        {
            byte[] keyBytes = Convert.FromBase64String(base64Key);
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.CreateKey(keyBytes);
            return (ECPrivateKeyParameters)privateKey;
        }

        /// <summary>
        /// 将公钥转换为16进制字符串
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>16进制字符串</returns>
        public static string PublicKeyToHex(ECPublicKeyParameters publicKey)
        {
            byte[] encodedKey = publicKey.Q.GetEncoded(false);
            return Hex.ToHexString(encodedKey).ToUpper();
        }

        /// <summary>
        /// 将私钥转换为16进制字符串
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>16进制字符串</returns>
        public static string PrivateKeyToHex(ECPrivateKeyParameters privateKey)
        {
            byte[] d = privateKey.D.ToByteArrayUnsigned();
            return Hex.ToHexString(d).ToUpper();
        }

        /// <summary>
        /// 从16进制字符串解析公钥
        /// </summary>
        /// <param name="hexPublicKey">16进制格式的公钥</param>
        /// <returns>SM2公钥</returns>
        public static ECPublicKeyParameters ParsePublicKeyFromHex(string hexPublicKey)
        {
            byte[] keyBytes = Hex.Decode(hexPublicKey);
            ECPoint point = SM2_ECX9_PARAMS.Curve.DecodePoint(keyBytes);
            return new ECPublicKeyParameters("EC", point, SM2_DOMAIN_PARAMS);
        }

        /// <summary>
        /// 从16进制字符串解析私钥
        /// </summary>
        /// <param name="hexPrivateKey">16进制格式的私钥</param>
        /// <returns>SM2私钥</returns>
        public static ECPrivateKeyParameters ParsePrivateKeyFromHex(string hexPrivateKey)
        {
            BigInteger d = new BigInteger(hexPrivateKey, 16);
            return new ECPrivateKeyParameters("EC", d, SM2_DOMAIN_PARAMS);
        }

        #region SM2加密解密

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>加密后的数据（Base64编码）</returns>
        public static string Encrypt(byte[] data, ECPublicKeyParameters publicKey)
        {
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
        public static string Encrypt(byte[] data, string publicKeyBase64)
        {
            ECPublicKeyParameters publicKey;
            try
            {
                publicKey = ParseRawPublicKeyFromBase64(publicKeyBase64);
            }
            catch
            {
                publicKey = ParsePublicKeyFromBase64(publicKeyBase64);
            }
            return Encrypt(data, publicKey);
        }

        /// <summary>
        /// SM2加密
        /// </summary>
        /// <param name="plainText">待加密字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>加密后的字符串（Base64编码）</returns>
        public static string Encrypt(string plainText, ECPublicKeyParameters publicKey, Encoding encoding = null)
        {
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
        public static string Encrypt(string plainText, string publicKeyBase64, Encoding encoding = null)
        {
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
        public static byte[] Decrypt(string encryptedData, ECPrivateKeyParameters privateKey)
        {
            byte[] data = Convert.FromBase64String(encryptedData);
            SM2Engine engine = new SM2Engine();
            engine.Init(false, privateKey);
            return engine.ProcessBlock(data, 0, data.Length);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密数据的Base64编码</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <returns>解密后的数据</returns>
        public static byte[] Decrypt(string encryptedData, string privateKeyBase64)
        {
            // 尝试使用原始私钥值解析，如果失败则回退到完整ASN.1格式解析
            ECPrivateKeyParameters privateKey;
            try
            {
                privateKey = ParseRawPrivateKeyFromBase64(privateKeyBase64);
            }
            catch
            {
                privateKey = ParsePrivateKeyFromBase64(privateKeyBase64);
            }
            return Decrypt(encryptedData, privateKey);
        }

        /// <summary>
        /// SM2解密
        /// </summary>
        /// <param name="encryptedData">加密的Base64字符串</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>解密后的原文</returns>
        public static string DecryptToString(string encryptedData, ECPrivateKeyParameters privateKey, Encoding encoding = null)
        {
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
        public static string DecryptToString(string encryptedData, string privateKeyBase64, Encoding encoding = null)
        {
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
        public static string SignSm3WithSm2(byte[] data, ECPrivateKeyParameters privateKey)
        {
            var signer = SignerUtilities.GetSigner("SM3withSM2");
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
        public static string SignSm3WithSm2(string data, ECPrivateKeyParameters privateKey, Encoding encoding = null)
        {
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
        public static string SignSm3WithSm2(byte[] data, string privateKeyBase64)
        {
            ECPrivateKeyParameters privateKey;
            try
            {
                privateKey = ParsePrivateKeyFromBase64(privateKeyBase64);
            }
            catch
            {
                privateKey = ParseRawPrivateKeyFromBase64(privateKeyBase64);
            }
            return SignSm3WithSm2(data, privateKey);
        }

        /// <summary>
        /// 使用SM3WithSM2算法对字符串数据进行签名
        /// </summary>
        /// <param name="data">要签名的字符串</param>
        /// <param name="privateKeyBase64">SM2私钥的Base64编码</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>签名结果的16进制字符串</returns>
        public static string SignSm3WithSm2(string data, string privateKeyBase64, Encoding encoding = null)
        {
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
        public static bool VerifySm3WithSm2(byte[] data, string signature, ECPublicKeyParameters publicKey)
        {
            var signer = SignerUtilities.GetSigner("SM3withSM2");
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signBytes = Hex.Decode(signature);
            return signer.VerifySignature(signBytes);
        }

        /// <summary>
        /// 验证SM3WithSM2签名
        /// </summary>
        /// <param name="data">原始字符串</param>
        /// <param name="signature">签名的16进制字符串</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>验证结果</returns>
        public static bool VerifySm3WithSm2(string data, string signature, ECPublicKeyParameters publicKey, Encoding encoding = null)
        {
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
        public static bool VerifySm3WithSm2(byte[] data, string signature, string publicKeyBase64)
        {
            ECPublicKeyParameters publicKey;
            try
            {
                publicKey = ParsePublicKeyFromBase64(publicKeyBase64);
            }
            catch
            {
                publicKey = ParseRawPublicKeyFromBase64(publicKeyBase64);
            }
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
        public static bool VerifySm3WithSm2(string data, string signature, string publicKeyBase64, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return VerifySm3WithSm2(dataBytes, signature, publicKeyBase64);
        }

        #endregion

        #region 辅助方法

        /// <summary>
        /// 计算SM3哈希值
        /// </summary>
        /// <param name="data">要计算哈希的数据</param>
        /// <returns>哈希值的16进制字符串</returns>
        public static string Sm3Hash(byte[] data)
        {
            Org.BouncyCastle.Crypto.Digests.SM3Digest sm3 = new Org.BouncyCastle.Crypto.Digests.SM3Digest();
            sm3.BlockUpdate(data, 0, data.Length);
            byte[] hash = new byte[sm3.GetDigestSize()];
            sm3.DoFinal(hash, 0);
            return Hex.ToHexString(hash).ToUpper();
        }

        /// <summary>
        /// 计算字符串的SM3哈希值
        /// </summary>
        /// <param name="data">要计算哈希的字符串</param>
        /// <param name="encoding">字符编码（默认UTF-8）</param>
        /// <returns>哈希值的16进制字符串</returns>
        public static string Sm3Hash(string data, Encoding encoding = null)
        {
            encoding = encoding ?? Encoding.UTF8;
            byte[] dataBytes = encoding.GetBytes(data);
            return Sm3Hash(dataBytes);
        }

        #endregion

        /// <summary>
        /// 从Base64编码的原始椭圆曲线点创建SM2公钥
        /// </summary>
        /// <param name="base64Key">Base64编码的原始公钥点</param>
        /// <returns>SM2公钥参数</returns>
        public static ECPublicKeyParameters ParseRawPublicKeyFromBase64(string base64Key)
        {
            byte[] keyBytes = Convert.FromBase64String(base64Key);
            ECPoint point = SM2_ECX9_PARAMS.Curve.DecodePoint(keyBytes);
            return new ECPublicKeyParameters("EC", point, SM2_DOMAIN_PARAMS);
        }

        /// <summary>
        /// 从Base64编码的原始私钥值创建SM2私钥
        /// </summary>
        /// <param name="base64Key">Base64编码的原始私钥值</param>
        /// <returns>SM2私钥参数</returns>
        public static ECPrivateKeyParameters ParseRawPrivateKeyFromBase64(string base64Key)
        {
            byte[] keyBytes = Convert.FromBase64String(base64Key);
            BigInteger d = new BigInteger(1, keyBytes);
            return new ECPrivateKeyParameters("EC", d, SM2_DOMAIN_PARAMS);
        }
    }
}
