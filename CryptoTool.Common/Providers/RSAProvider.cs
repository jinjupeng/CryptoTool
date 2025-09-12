using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common.Providers
{
    /// <summary>
    /// RSA工具类，支持RSA、RSA2算法，支持PKCS1和PKCS8格式转换
    /// </summary>
    public class RSAProvider : IAsymmetricCryptoProvider
    {
        #region IAsymmetricCryptoProvider 实现

        /// <summary>
        /// 算法类型
        /// </summary>
        public AlgorithmType AlgorithmType => AlgorithmType.RSA;

        /// <summary>
        /// 生成密钥对（接口方法）- 返回PEM格式
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对（公钥，私钥）PEM格式</returns>
        public (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048)
        {
            return GenerateKeyPair(keySize, KeyFormat.PEM);
        }

        /// <summary>
        /// 生成密钥对 - 指定输出格式
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="format">密钥格式</param>
        /// <returns>密钥对（指定格式）</returns>
        public (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize, KeyFormat format)
        {
            var keyPair = GenerateKeyPairInternal((int)keySize);
            var publicKey = (RsaKeyParameters)keyPair.Public;
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            var publicKeyString = GeneratePublicKeyString(publicKey, format);
            var privateKeyString = GeneratePrivateKeyString(privateKey, format);

            return (publicKeyString, privateKeyString);
        }

        /// <summary>
        /// 使用公钥加密（接口方法）- 返回Base64格式
        /// </summary>
        public string EncryptWithPublicKey(string plaintext, string publicKey)
        {
            return EncryptWithPublicKey(plaintext, publicKey, RSAPadding.PKCS1, null);
        }

        /// <summary>
        /// 使用公钥加密 - 指定编码和填充方式
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文（Base64格式）</returns>
        public string EncryptWithPublicKey(string plaintext, string publicKey, RSAPadding padding, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空", nameof(plaintext));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var plainTextBytes = encoding.GetBytes(plaintext);
            var cipherTextBytes = EncryptWithPublicKey(plainTextBytes, publicKey, padding);

            return Convert.ToBase64String(cipherTextBytes);
        }

        /// <summary>
        /// 使用公钥加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <returns>密文字节数组</returns>
        public byte[] EncryptWithPublicKey(byte[] data, string publicKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);
            return EncryptWithPublicKey(data, rsaPublicKey, padding);
        }

        /// <summary>
        /// 使用私钥解密（接口方法）- 输入Base64格式
        /// </summary>
        public string DecryptWithPrivateKey(string ciphertext, string privateKey)
        {
            return DecryptWithPrivateKey(ciphertext, privateKey, RSAPadding.PKCS1, null);
        }

        /// <summary>
        /// 使用私钥解密 - 指定编码和填充方式
        /// </summary>
        /// <param name="ciphertext">密文（Base64格式）</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        public string DecryptWithPrivateKey(string ciphertext, string privateKey, RSAPadding padding, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("密文不能为空", nameof(ciphertext));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var cipherTextBytes = Convert.FromBase64String(ciphertext);
            var plainTextBytes = DecryptWithPrivateKey(cipherTextBytes, privateKey, padding);

            return encoding.GetString(plainTextBytes);
        }

        /// <summary>
        /// 使用私钥解密字节数组
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <returns>明文字节数组</returns>
        public byte[] DecryptWithPrivateKey(byte[] data, string privateKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            return DecryptWithPrivateKey(data, rsaPrivateKey, padding);
        }

        /// <summary>
        /// 签名（接口方法）- 返回Base64格式
        /// </summary>
        public string Sign(string data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            return Sign(data, privateKey, algorithm, null);
        }

        /// <summary>
        /// 签名 - 指定编码方式
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名（Base64格式）</returns>
        public string Sign(string data, string privateKey, SignatureAlgorithm algorithm, Encoding encoding)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = Sign(dataBytes, privateKey, algorithm);

            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// 签名字节数组
        /// </summary>
        /// <param name="data">待签名数据字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>签名字节数组</returns>
        public byte[] Sign(byte[] data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("待签名数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            return SignBytes(data, rsaPrivateKey, algorithm);
        }

        /// <summary>
        /// 验签（接口方法）- 输入Base64格式签名
        /// </summary>
        public bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            return Verify(data, signature, publicKey, algorithm, null);
        }

        /// <summary>
        /// 验签 - 指定编码方式
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名（Base64格式）</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验签结果</returns>
        public bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm, Encoding encoding)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = Convert.FromBase64String(signature);

            return Verify(dataBytes, signatureBytes, publicKey, algorithm);
        }

        /// <summary>
        /// 验签字节数组
        /// </summary>
        /// <param name="data">原始数据字节数组</param>
        /// <param name="signature">签名字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>验签结果</returns>
        public bool Verify(byte[] data, byte[] signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
        {
            if (data == null || signature == null || data.Length == 0 || signature.Length == 0)
                return false;

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);
            return VerifyBytes(data, signature, rsaPublicKey, algorithm);
        }

        #endregion

        #region 基础加解密方法

        /// <summary>
        /// 加密字符串 - 基础方法
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文（Base64格式）</returns>
        public string EncryptBasic(string plaintext, string publicKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空", nameof(plaintext));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var plainTextBytes = encoding.GetBytes(plaintext);
            var cipherTextBytes = EncryptBytes(plainTextBytes, publicKey);

            return Convert.ToBase64String(cipherTextBytes);
        }

        /// <summary>
        /// 解密字符串 - 基础方法
        /// </summary>
        /// <param name="cipherText">密文（Base64格式）</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        public string DecryptBasic(string cipherText, string privateKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentException("密文不能为空", nameof(cipherText));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var cipherTextBytes = Convert.FromBase64String(cipherText);
            var plainTextBytes = DecryptBytes(cipherTextBytes, privateKey);

            return encoding.GetString(plainTextBytes);
        }

        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文</returns>
        public byte[] EncryptBytes(byte[] data, string publicKey)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);
            return EncryptWithPublicKey(data, rsaPublicKey, RSAPadding.PKCS1);
        }

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文</returns>
        public byte[] DecryptBytes(byte[] data, string privateKey)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            return DecryptWithPrivateKey(data, rsaPrivateKey, RSAPadding.PKCS1);
        }

        /// <summary>
        /// 签名（基础方法）- 返回Base64格式
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名（Base64格式）</returns>
        public string SignBasic(string data, string privateKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            var signatureBytes = SignBytes(dataBytes, rsaPrivateKey, SignatureAlgorithm.SHA256withRSA);

            return Convert.ToBase64String(signatureBytes);
        }

        /// <summary>
        /// 验证签名（基础方法）- 输入Base64格式签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名（Base64格式）</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验证结果</returns>
        public bool VerifyBasic(string data, string signature, string publicKey, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = Convert.FromBase64String(signature);
            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);

            return VerifyBytes(dataBytes, signatureBytes, rsaPublicKey, SignatureAlgorithm.SHA256withRSA);
        }

        #endregion

        #region 密钥生成

        /// <summary>
        /// 生成RSA密钥对（内部方法）
        /// </summary>
        /// <param name="keySize">密钥长度（1024、2048、4096）</param>
        /// <returns>密钥对</returns>
        public static AsymmetricCipherKeyPair GenerateKeyPairInternal(int keySize = 2048)
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
        /// <returns>公钥字符串</returns>
        public static string GeneratePublicKeyString(RsaKeyParameters publicKey, KeyFormat format = KeyFormat.PEM)
        {
            switch (format)
            {
                case KeyFormat.PEM:
                    return PublicKeyToPem(publicKey);
                case KeyFormat.Base64:
                    return PublicKeyToBase64(publicKey);
                case KeyFormat.Hex:
                    return PublicKeyToHex(publicKey);
                default:
                    throw new ArgumentException($"不支持的输出格式[{format}]");
            }
        }

        /// <summary>
        /// 生成私钥字符串
        /// </summary>
        /// <param name="privateKey">私钥对象</param>
        /// <param name="format">输出格式</param>
        /// <returns>私钥字符串</returns>
        public static string GeneratePrivateKeyString(RsaPrivateCrtKeyParameters privateKey, KeyFormat format = KeyFormat.PEM)
        {
            switch (format)
            {
                case KeyFormat.PEM:
                    return PrivateKeyToPem(privateKey);
                case KeyFormat.Base64:
                    return PrivateKeyToBase64(privateKey);
                case KeyFormat.Hex:
                    return PrivateKeyToHex(privateKey);
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
        /// <returns>PEM格式公钥</returns>
        public static string PublicKeyToPem(RsaKeyParameters publicKey)
        {
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(publicKey);
                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// 私钥转PEM格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>PEM格式私钥</returns>
        public static string PrivateKeyToPem(RsaPrivateCrtKeyParameters privateKey)
        {
            using (var stringWriter = new StringWriter())
            {
                var pemWriter = new PemWriter(stringWriter);
                pemWriter.WriteObject(privateKey);
                return stringWriter.ToString();
            }
        }

        /// <summary>
        /// 公钥转Base64格式
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns>Base64格式公钥</returns>
        public static string PublicKeyToBase64(RsaKeyParameters publicKey)
        {
            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            return Convert.ToBase64String(publicKeyInfo.GetDerEncoded());
        }

        /// <summary>
        /// 私钥转Base64格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>Base64格式私钥</returns>
        public static string PrivateKeyToBase64(RsaPrivateCrtKeyParameters privateKey)
        {
            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return Convert.ToBase64String(privateKeyInfo.GetDerEncoded());
        }

        /// <summary>
        /// 公钥转Hex格式
        /// </summary>
        /// <param name="publicKey">公钥</param>
        /// <returns>Hex格式公钥</returns>
        public static string PublicKeyToHex(RsaKeyParameters publicKey)
        {
            var base64Key = PublicKeyToBase64(publicKey);
            var keyBytes = Convert.FromBase64String(base64Key);
            return CryptoCommonUtil.ConvertToHexString(keyBytes);
        }

        /// <summary>
        /// 私钥转Hex格式
        /// </summary>
        /// <param name="privateKey">私钥</param>
        /// <returns>Hex格式私钥</returns>
        public static string PrivateKeyToHex(RsaPrivateCrtKeyParameters privateKey)
        {
            var base64Key = PrivateKeyToBase64(privateKey);
            var keyBytes = Convert.FromBase64String(base64Key);
            return CryptoCommonUtil.ConvertToHexString(keyBytes);
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

        #endregion

        #region 加解密核心方法

        /// <summary>
        /// RSA加密（字节数组）
        /// </summary>
        /// <param name="plaintext">明文字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式</param>
        /// <returns>密文字节数组</returns>
        public static byte[] EncryptWithPublicKey(byte[] plaintext, RsaKeyParameters publicKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (plaintext == null || plaintext.Length == 0)
                throw new ArgumentException("明文不能为空");

            var engine = GetCipherEngine(padding);
            engine.Init(true, publicKey);
            return engine.ProcessBlock(plaintext, 0, plaintext.Length);
        }

        /// <summary>
        /// RSA解密（字节数组）
        /// </summary>
        /// <param name="ciphertext">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式</param>
        /// <returns>明文字节数组</returns>
        public static byte[] DecryptWithPrivateKey(byte[] ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding = RSAPadding.PKCS1)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("密文不能为空");

            var engine = GetCipherEngine(padding);
            engine.Init(false, privateKey);
            return engine.ProcessBlock(ciphertext, 0, ciphertext.Length);
        }

        #endregion

        #region 签名与验签核心方法

        /// <summary>
        /// RSA签名（字节数组）
        /// </summary>
        /// <param name="data">待签名数据字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>签名字节数组</returns>
        public static byte[] SignBytes(byte[] data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
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
        /// RSA验签（字节数组）
        /// </summary>
        /// <param name="data">原始数据字节数组</param>
        /// <param name="signature">签名字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>验签结果</returns>
        public static bool VerifyBytes(byte[] data, byte[] signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA)
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

        #endregion
    }
}