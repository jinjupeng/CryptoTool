using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Utils;
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
using Org.BouncyCastle.X509;
using System;
using System.Text;
using System.Threading.Tasks;

namespace CryptoTool.Common.Providers.GM
{
    /// <summary>
    /// SM2国密算法工具类，提供SM2非对称加密、签名验签等功能。
    /// SM2是一种基于椭圆曲线密码（ECC）的公钥密码算法，由国家密码管理局发布。
    /// </summary>
    public class SM2Provider : IAsymmetricCryptoProvider
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
        /// 65 bytes (uncompressed point for 256-bit curve) 加密过程中生成的随机椭圆曲线点，未压缩格式下长度为65字节
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
        /// 创建ECDomainParameters对象，包含曲线的基本参数，如曲线、生成元G、阶N和系数H
        /// </summary>
        private static readonly ECDomainParameters SM2_DOMAIN_PARAMS = new ECDomainParameters(
            SM2_ECX9_PARAMS.Curve,
            SM2_ECX9_PARAMS.G,
            SM2_ECX9_PARAMS.N,
            SM2_ECX9_PARAMS.H);

        #endregion

        #region IAsymmetricCryptoProvider 实现

        /// <summary>
        /// 算法类型
        /// </summary>
        public AlgorithmType AlgorithmType => AlgorithmType.SM2;

        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文</returns>
        public string Encrypt(string plainText, string publicKey, OutputFormat outputFormat = OutputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentException("明文不能为空", nameof(plainText));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var plainTextBytes = encoding.GetBytes(plainText);
            var cipherTextBytes = Encrypt(plainTextBytes, publicKey);

            return CryptoCommonUtil.BytesToString(cipherTextBytes, outputFormat);
        }

        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        public string Decrypt(string cipherText, string privateKey, InputFormat inputFormat = InputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentException("密文不能为空", nameof(cipherText));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var cipherTextBytes = CryptoCommonUtil.StringToBytes(cipherText, inputFormat);
            var plainTextBytes = Decrypt(cipherTextBytes, privateKey);

            return encoding.GetString(plainTextBytes);
        }

        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文</returns>
        public byte[] Encrypt(byte[] data, string publicKey)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            var ecPublicKey = ParsePublicKeyFromBase64(publicKey);
            return Encrypt(data, ecPublicKey, SM2CipherFormat.C1C3C2);
        }

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文</returns>
        public byte[] Decrypt(byte[] data, string privateKey)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            var ecPrivateKey = ParsePrivateKeyFromBase64(privateKey);
            return Decrypt(data, ecPrivateKey, SM2CipherFormat.C1C3C2);
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名</returns>
        public string Sign(string data, string privateKey, OutputFormat outputFormat = OutputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var ecPrivateKey = ParsePrivateKeyFromBase64(privateKey);
            var signatureBytes = Sign(dataBytes, ecPrivateKey, SM2SignatureFormat.ASN1);

            return CryptoCommonUtil.BytesToString(signatureBytes, outputFormat);
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验证结果</returns>
        public bool Verify(string data, string signature, string publicKey, InputFormat inputFormat = InputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = CryptoCommonUtil.StringToBytes(signature, inputFormat);
            var ecPublicKey = ParsePublicKeyFromBase64(publicKey);

            return Verify(dataBytes, signatureBytes, ecPublicKey, SM2SignatureFormat.ASN1);
        }

        /// <summary>
        /// 生成密钥对（接口方法）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对（公钥，私钥）</returns>
        public (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048)
        {
            var keyPair = GenerateKeyPairInternal(keySize, OutputFormat.Base64);
            return (keyPair.publicKey, keyPair.privateKey);
        }

        /// <summary>
        /// 生成密钥对（内部方法）
        /// </summary>
        /// <param name="keySize">密钥长度（SM2固定为256位，忽略此参数）</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密钥对（公钥，私钥）</returns>
        public (string publicKey, string privateKey) GenerateKeyPairInternal(KeySize keySize = KeySize.Key256, OutputFormat outputFormat = OutputFormat.Base64)
        {
            var keyPair = GenerateKeyPair();
            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            var privateKey = (ECPrivateKeyParameters)keyPair.Private;

            var publicKeyString = PublicKeyToBase64(publicKey);
            var privateKeyString = PrivateKeyToBase64(privateKey);

            return (publicKeyString, privateKeyString);
        }

        /// <summary>
        /// 使用公钥加密（接口方法）
        /// </summary>
        public string EncryptWithPublicKey(string plaintext, string publicKey, OutputFormat outputFormat = OutputFormat.Base64)
        {
            return Encrypt(plaintext, publicKey, outputFormat);
        }

        /// <summary>
        /// 使用私钥解密（接口方法）
        /// </summary>
        public string DecryptWithPrivateKey(string ciphertext, string privateKey, InputFormat inputFormat = InputFormat.Base64)
        {
            return Decrypt(ciphertext, privateKey, inputFormat);
        }

        /// <summary>
        /// 签名（接口方法）
        /// </summary>
        public string Sign(string data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SM3withSM2, OutputFormat outputFormat = OutputFormat.Base64)
        {
            var signatureBytes = Sign(Encoding.UTF8.GetBytes(data), ParsePrivateKeyFromBase64(privateKey));
            return CryptoCommonUtil.BytesToString(signatureBytes, outputFormat);
        }

        /// <summary>
        /// 验签（接口方法）
        /// </summary>
        public bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SM3withSM2, InputFormat inputFormat = InputFormat.Base64)
        {
            var signatureBytes = CryptoCommonUtil.StringToBytes(signature, inputFormat);
            return Verify(Encoding.UTF8.GetBytes(data), signatureBytes, ParsePublicKeyFromBase64(publicKey));
        }

        /// <summary>
        /// 加密字符串（ICryptoProvider接口实现）
        /// </summary>
        public string Encrypt(string plaintext, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null)
        {
            return Encrypt(plaintext, key, outputFormat);
        }

        /// <summary>
        /// 解密字符串（ICryptoProvider接口实现）
        /// </summary>
        public string Decrypt(string ciphertext, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, InputFormat inputFormat = InputFormat.Base64, string iv = null)
        {
            return Decrypt(ciphertext, key, inputFormat);
        }

        /// <summary>
        /// 加密字节数组（ICryptoProvider接口实现）
        /// </summary>
        public byte[] Encrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            // SM2不支持字节数组密钥，需要转换
            string keyString = Convert.ToBase64String(key);
            return Encrypt(data, keyString);
        }

        /// <summary>
        /// 解密字节数组（ICryptoProvider接口实现）
        /// </summary>
        public byte[] Decrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            // SM2不支持字节数组密钥，需要转换
            string keyString = Convert.ToBase64String(key);
            return Decrypt(data, keyString);
        }

        /// <summary>
        /// 加密文件（ICryptoProvider接口实现）
        /// </summary>
        public void EncryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            throw new NotSupportedException("SM2不支持文件加密，请使用对称加密算法");
        }

        /// <summary>
        /// 解密文件（ICryptoProvider接口实现）
        /// </summary>
        public void DecryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            throw new NotSupportedException("SM2不支持文件解密，请使用对称加密算法");
        }

        /// <summary>
        /// 异步加密文件（ICryptoProvider接口实现）
        /// </summary>
        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 异步解密文件（ICryptoProvider接口实现）
        /// </summary>
        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, key, mode, padding, iv));
        }

        /// <summary>
        /// 生成密钥（ICryptoProvider接口实现）
        /// </summary>
        public string GenerateKey(KeySize keySize = KeySize.Key256, OutputFormat format = OutputFormat.Base64)
        {
            var keyPair = GenerateKeyPairInternal(KeySize.Key2048, format);
            return keyPair.privateKey;
        }

        /// <summary>
        /// 生成初始化向量（ICryptoProvider接口实现）
        /// </summary>
        public string GenerateIV(OutputFormat format = OutputFormat.Base64)
        {
            throw new NotSupportedException("SM2不需要初始化向量");
        }

        /// <summary>
        /// 验证密钥有效性（ICryptoProvider接口实现）
        /// </summary>
        public bool ValidateKey(string key, InputFormat format = InputFormat.UTF8)
        {
            try
            {
                if (format == InputFormat.UTF8)
                {
                    // 尝试解析Base64格式
                    ParsePrivateKeyFromBase64(key);
                    return true;
                }
                else
                {
                    // 尝试解析Base64格式
                    byte[] keyBytes = Convert.FromBase64String(key);
                    return keyBytes.Length > 0;
                }
            }
            catch
            {
                return false;
            }
        }

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
        /// 将SM2公钥转换为Base64字符串（SubjectPublicKeyInfo格式，包含完整椭圆曲线参数）
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>Base64编码的公钥</returns>
        /// <exception cref="ArgumentNullException">当公钥为null时抛出</exception>
        public static string PublicKeyToBase64(ECPublicKeyParameters publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");

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
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");

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
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");

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
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");

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
                throw new ArgumentNullException(nameof(base64PublicKey), "Base64格式公钥不能为空");

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
                throw new ArgumentNullException(nameof(base64PrivateKey), "Base64格式私钥不能为空");

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

        #region SM2加密解密

        /// <summary>
        /// SM2加密（字节数组）
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>加密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static byte[] Encrypt(byte[] data, ECPublicKeyParameters publicKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("待加密数据不能为空或长度为0", nameof(data));

            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");

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

            return encryptedBytes;
        }

        /// <summary>
        /// SM2解密（字节数组）
        /// </summary>
        /// <param name="encryptedData">加密数据</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">密文格式（默认为C1C3C2）</param>
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        /// <exception cref="CryptographicException">解密失败时抛出</exception>
        public static byte[] Decrypt(byte[] encryptedData, ECPrivateKeyParameters privateKey, SM2CipherFormat format = SM2CipherFormat.C1C3C2)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new ArgumentException("加密数据不能为空或长度为0", nameof(encryptedData));

            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");

            // 根据输入格式，统一转换为BouncyCastle引擎能处理的C1C2C3格式
            byte[] encryptedBytes = encryptedData;
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

        #endregion

        #region SM2签名验签

        /// <summary>
        /// 使用SM3WithSM2算法对数据进行签名（字节数组）
        /// </summary>
        /// <param name="data">要签名的数据</param>
        /// <param name="privateKey">SM2私钥</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>签名结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static byte[] Sign(byte[] data, ECPrivateKeyParameters privateKey, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("待签名数据不能为空或长度为0", nameof(data));

            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");

            var signer = SignerUtilities.GetSigner(SM3_WITH_SM2);
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signature = signer.GenerateSignature(); // BouncyCastle默认生成ASN.1格式

            if (format == SM2SignatureFormat.RS)
            {
                signature = ConvertAsn1ToRs(signature);
            }

            return signature;
        }

        /// <summary>
        /// 验证SM3WithSM2签名（字节数组）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">SM2公钥</param>
        /// <param name="format">签名格式（默认为ASN1）</param>
        /// <returns>验证结果</returns>
        /// <exception cref="ArgumentNullException">当参数为null时抛出</exception>
        /// <exception cref="ArgumentException">当数据长度为0时抛出</exception>
        public static bool Verify(byte[] data, byte[] signature, ECPublicKeyParameters publicKey, SM2SignatureFormat format = SM2SignatureFormat.ASN1)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("原始数据不能为空或长度为0", nameof(data));

            if (signature == null || signature.Length == 0)
                throw new ArgumentException("签名不能为空或长度为0", nameof(signature));

            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");

            byte[] signBytes = signature;
            if (format == SM2SignatureFormat.RS)
            {
                signBytes = ConvertRsToAsn1(signBytes);
            }

            var signer = SignerUtilities.GetSigner(SM3_WITH_SM2);
            signer.Init(false, publicKey);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signBytes);
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
                throw new ArgumentException("无效的C1C2C3格式密文", nameof(c1c2c3));

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
                throw new ArgumentException("无效的C1C3C2格式密文", nameof(c1c3c2));

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

            ECPoint c1Point = SM2_ECX9_PARAMS.Curve.CreatePoint(x, y);
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
                throw new ArgumentException("无效的RS格式签名", nameof(rs));

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
                throw new ArgumentException("ASN.1格式签名不能为空", nameof(asn1));

            try
            {
                Asn1Sequence sequence = Asn1Sequence.GetInstance(asn1);
                if (sequence.Count != 2)
                    throw new ArgumentException("ASN.1签名格式错误：应包含两个元素（R和S）");

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
                throw new ArgumentException("BigInteger不能为null");

            // 对于SM2P256v1，R和S的长度应为32字节
            byte[] rs = bigInt.ToByteArrayUnsigned();

            // 如果长度正好是32字节，直接返回
            if (rs.Length == SM2_RS_LENGTH)
                return rs;

            // 如果长度小于32字节，则在前面补0
            if (rs.Length < SM2_RS_LENGTH)
            {
                byte[] result = new byte[SM2_RS_LENGTH];
                Buffer.BlockCopy(rs, 0, result, SM2_RS_LENGTH - rs.Length, rs.Length);
                return result;
            }

            // 如果长度是33字节且第一个字节是0（Java BigInteger的符号位），则移除符号位
            if (rs.Length == SM2_RS_LENGTH + 1 && rs[0] == 0)
                return Arrays.CopyOfRange(rs, 1, SM2_RS_LENGTH + 1);

            // 其他异常情况
            throw new ArgumentException($"BigInteger转换为固定长度字节数组时发生意外长度: {rs.Length}。预期长度: {SM2_RS_LENGTH}", nameof(bigInt));
        }

        #endregion

        #region 16进制格式密钥转换（兼容旧版本）

        /// <summary>
        /// 将SM2公钥转换为16进制字符串
        /// </summary>
        /// <param name="publicKey">SM2公钥</param>
        /// <returns>16进制编码的公钥</returns>
        public static string PublicKeyToHex(ECPublicKeyParameters publicKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey), "公钥不能为空");

            byte[] rawKeyBytes = publicKey.Q.GetEncoded(false);
            return CryptoCommonUtil.ConvertToHexString(rawKeyBytes, true);
        }

        /// <summary>
        /// 将SM2私钥转换为16进制字符串
        /// </summary>
        /// <param name="privateKey">SM2私钥</param>
        /// <returns>16进制编码的私钥</returns>
        public static string PrivateKeyToHex(ECPrivateKeyParameters privateKey)
        {
            if (privateKey == null)
                throw new ArgumentNullException(nameof(privateKey), "私钥不能为空");

            byte[] rawKeyBytes = privateKey.D.ToByteArrayUnsigned();
            // 确保私钥长度为32字节
            if (rawKeyBytes.Length < 32)
            {
                byte[] paddedKey = new byte[32];
                Buffer.BlockCopy(rawKeyBytes, 0, paddedKey, 32 - rawKeyBytes.Length, rawKeyBytes.Length);
                rawKeyBytes = paddedKey;
            }
            return CryptoCommonUtil.ConvertToHexString(rawKeyBytes, true);
        }

        /// <summary>
        /// 从16进制字符串解析SM2公钥
        /// </summary>
        /// <param name="hexPublicKey">16进制编码的公钥</param>
        /// <returns>SM2公钥</returns>
        public static ECPublicKeyParameters ParsePublicKeyFromHex(string hexPublicKey)
        {
            if (string.IsNullOrEmpty(hexPublicKey))
                throw new ArgumentNullException(nameof(hexPublicKey), "16进制格式公钥不能为空");

            try
            {
                byte[] publicKeyBytes = CryptoCommonUtil.ConvertFromHexString(hexPublicKey);
                var q = SM2_ECX9_PARAMS.Curve.DecodePoint(publicKeyBytes);
                return new ECPublicKeyParameters(q, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex)
            {
                throw new FormatException("无效的16进制公钥格式", ex);
            }
        }

        /// <summary>
        /// 从16进制字符串解析SM2私钥
        /// </summary>
        /// <param name="hexPrivateKey">16进制编码的私钥</param>
        /// <returns>SM2私钥</returns>
        public static ECPrivateKeyParameters ParsePrivateKeyFromHex(string hexPrivateKey)
        {
            if (string.IsNullOrEmpty(hexPrivateKey))
                throw new ArgumentNullException(nameof(hexPrivateKey), "16进制格式私钥不能为空");

            try
            {
                byte[] privateKeyBytes = CryptoCommonUtil.ConvertFromHexString(hexPrivateKey);
                BigInteger d = new BigInteger(1, privateKeyBytes);
                return new ECPrivateKeyParameters(d, SM2_DOMAIN_PARAMS);
            }
            catch (Exception ex)
            {
                throw new FormatException("无效的16进制私钥格式", ex);
            }
        }

        #endregion

        #region 静态工具方法

        /// <summary>
        /// SM3withSM2签名（静态方法）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>十六进制签名</returns>
        public static string SignSm3WithSm2(byte[] data, ECPrivateKeyParameters privateKey)
        {
            var signatureBytes = Sign(data, privateKey);
            return CryptoCommonUtil.ConvertToHexString(signatureBytes, true);
        }

        /// <summary>
        /// SM3withSM2验签（静态方法）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">十六进制签名</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>验签结果</returns>
        public static bool VerifySm3WithSm2(byte[] data, string signature, ECPublicKeyParameters publicKey)
        {
            var signatureBytes = CryptoCommonUtil.ConvertFromHexString(signature);
            return Verify(data, signatureBytes, publicKey);
        }

        #endregion
    }
}