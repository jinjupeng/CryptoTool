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

            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);
            return Encrypt(data, rsaPublicKey, RSAPadding.PKCS1);
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

            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            return Decrypt(data, rsaPrivateKey, RSAPadding.PKCS1);
        }

        /// <summary>
        /// 签名（基础方法）
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名</returns>
        public string SignBasic(string data, string privateKey, OutputFormat outputFormat = OutputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("数据不能为空", nameof(data));

            if (string.IsNullOrEmpty(privateKey))
                throw new ArgumentException("私钥不能为空", nameof(privateKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var rsaPrivateKey = ParsePrivateKeyFromPem(privateKey);
            var signatureBytes = Sign(dataBytes, rsaPrivateKey, SignatureAlgorithm.SHA256withRSA);

            return CryptoCommonUtil.BytesToString(signatureBytes, outputFormat);
        }

        /// <summary>
        /// 验证签名（基础方法）
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验证结果</returns>
        public bool VerifyBasic(string data, string signature, string publicKey, InputFormat inputFormat = InputFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            if (string.IsNullOrEmpty(publicKey))
                throw new ArgumentException("公钥不能为空", nameof(publicKey));

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = CryptoCommonUtil.StringToBytes(signature, inputFormat);
            var rsaPublicKey = ParsePublicKeyFromPem(publicKey);

            return Verify(dataBytes, signatureBytes, rsaPublicKey, SignatureAlgorithm.SHA256withRSA);
        }

        /// <summary>
        /// 生成密钥对（接口方法）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对（公钥，私钥）</returns>
        public (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048)
        {
            var keyPair = GenerateKeyPairInternal(keySize, OutputFormat.PEM);
            return (keyPair.publicKey, keyPair.privateKey);
        }

        /// <summary>
        /// 生成密钥对（内部方法）
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密钥对（公钥，私钥）</returns>
        public (string publicKey, string privateKey) GenerateKeyPairInternal(KeySize keySize = KeySize.Key2048, OutputFormat outputFormat = OutputFormat.PEM)
        {
            var keyPair = GenerateKeyPair((int)keySize);
            var publicKey = (RsaKeyParameters)keyPair.Public;
            var privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            var publicKeyString = GeneratePublicKeyString(publicKey, KeyFormat.PEM);
            var privateKeyString = GeneratePrivateKeyString(privateKey, KeyFormat.PEM);

            return (publicKeyString, privateKeyString);
        }

        #endregion

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
        public string Sign(string data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, OutputFormat outputFormat = OutputFormat.Base64)
        {
            return SignBasic(data, privateKey, outputFormat);
        }

        /// <summary>
        /// 验签（接口方法）
        /// </summary>
        public bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, InputFormat inputFormat = InputFormat.Base64)
        {
            return VerifyBasic(data, signature, publicKey, inputFormat);
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
            // RSA不支持字节数组密钥，需要转换
            string keyString = Convert.ToBase64String(key);
            return Encrypt(data, keyString);
        }

        /// <summary>
        /// 解密字节数组（ICryptoProvider接口实现）
        /// </summary>
        public byte[] Decrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null)
        {
            // RSA不支持字节数组密钥，需要转换
            string keyString = Convert.ToBase64String(key);
            return Decrypt(data, keyString);
        }

        /// <summary>
        /// 加密文件（ICryptoProvider接口实现）
        /// </summary>
        public void EncryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            throw new NotSupportedException("RSA不支持文件加密，请使用对称加密算法");
        }

        /// <summary>
        /// 解密文件（ICryptoProvider接口实现）
        /// </summary>
        public void DecryptFile(string inputFilePath, string outputFilePath, string key, CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null)
        {
            throw new NotSupportedException("RSA不支持文件解密，请使用对称加密算法");
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
            var keyPair = GenerateKeyPairInternal(keySize, format);
            return keyPair.privateKey;
        }

        /// <summary>
        /// 生成初始化向量（ICryptoProvider接口实现）
        /// </summary>
        public string GenerateIV(OutputFormat format = OutputFormat.Base64)
        {
            throw new NotSupportedException("RSA不需要初始化向量");
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
                    // 尝试解析PEM格式
                    ParsePrivateKeyFromPem(key);
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
            return BitConverter.ToString(keyBytes).Replace("-", "");
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
        public static string Encrypt(string plaintext, RsaKeyParameters publicKey, RSAPadding padding = RSAPadding.PKCS1, KeyFormat outputFormat = KeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(plaintext))
                throw new ArgumentException("明文不能为空");

            encoding = encoding ?? Encoding.UTF8;
            var plaintextBytes = encoding.GetBytes(plaintext);
            var ciphertextBytes = Encrypt(plaintextBytes, publicKey, padding);

            return outputFormat switch
            {
                KeyFormat.Base64 => Convert.ToBase64String(ciphertextBytes),
                KeyFormat.Hex => BitConverter.ToString(ciphertextBytes).Replace("-", ""),
                _ => throw new ArgumentException($"不支持的输出格式[{outputFormat}]")
            };
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
        public static string Decrypt(string ciphertext, RsaPrivateCrtKeyParameters privateKey, RSAPadding padding = RSAPadding.PKCS1, KeyFormat inputFormat = KeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(ciphertext))
                throw new ArgumentException("密文不能为空");

            encoding = encoding ?? Encoding.UTF8;

            byte[] ciphertextBytes = inputFormat switch
            {
                KeyFormat.Base64 => Convert.FromBase64String(ciphertext),
                KeyFormat.Hex => CryptoCommonUtil.ConvertFromHexString(ciphertext),
                _ => throw new ArgumentException($"不支持的输入格式{inputFormat}")
            };

            var plaintextBytes = Decrypt(ciphertextBytes, privateKey, padding);
            return encoding.GetString(plaintextBytes);
        }

        /// <summary>
        /// RSA解密（字节数组）
        /// </summary>
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
        public static string Sign(string data, RsaPrivateCrtKeyParameters privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, KeyFormat outputFormat = KeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data))
                throw new ArgumentException("待签名数据不能为空");

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);
            var signatureBytes = Sign(dataBytes, privateKey, algorithm);

            return outputFormat switch
            {
                KeyFormat.Base64 => Convert.ToBase64String(signatureBytes),
                KeyFormat.Hex => BitConverter.ToString(signatureBytes).Replace("-", ""),
                _ => throw new ArgumentException($"不支持的输出格式[{outputFormat}]")
            };
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
        public static bool Verify(string data, string signature, RsaKeyParameters publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA, KeyFormat inputFormat = KeyFormat.Base64, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(signature))
                return false;

            encoding = encoding ?? Encoding.UTF8;
            var dataBytes = encoding.GetBytes(data);

            byte[] signatureBytes = inputFormat switch
            {
                KeyFormat.Base64 => Convert.FromBase64String(signature),
                KeyFormat.Hex => CryptoCommonUtil.ConvertFromHexString(signature),
                _ => throw new ArgumentException($"不支持的输入格式[{inputFormat}]")
            };

            return Verify(dataBytes, signatureBytes, publicKey, algorithm);
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