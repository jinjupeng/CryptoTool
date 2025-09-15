using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Interfaces;
using CryptoTool.Algorithm.Utils;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoTool.Algorithm.Algorithms.RSA
{
    /// <summary>
    /// RSA加密算法实现
    /// </summary>
    public class RsaCrypto : IAsymmetricCrypto
    {
        public string AlgorithmName => "RSA";
        public CryptoAlgorithmType AlgorithmType => CryptoAlgorithmType.Asymmetric;

        private readonly int _keySize;
        private readonly string _keyFormat;
        private const int PKCS1_PADDING_SIZE = 11;

        /// <summary>
        /// 初始化RSA加密算法
        /// </summary>
        /// <param name="keySize">密钥长度，默认2048位</param>
        /// <param name="keyFormat">密钥格式，支持"pkcs1"或"pkcs8"，默认为"pkcs8"</param>
        public RsaCrypto(int keySize = 2048, string keyFormat = "pkcs8")
        {
            ValidateKeySize(keySize);
            ValidateKeyFormat(keyFormat);
            _keySize = keySize;
            _keyFormat = keyFormat.ToLower();
        }

        /// <summary>
        /// 加密 - 固定PKCS1填充模式
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Encrypt(byte[] data, byte[] publicKey)
        {
            ValidateEncryptInput(data, publicKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, publicKey);

                var maxDataLength = GetMaxDataLength(rsa.KeySize);
                if (data.Length > maxDataLength)
                {
                    return EncryptLargeData(data, rsa);
                }

                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("RSA加密失败", ex);
            }
        }

        /// <summary>
        /// 解密 - 固定PKCS1填充模式
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Decrypt(byte[] encryptedData, byte[] privateKey)
        {
            ValidateDecryptInput(encryptedData, privateKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, privateKey);

                var blockSize = rsa.KeySize / 8;
                if (encryptedData.Length > blockSize)
                {
                    return DecryptLargeData(encryptedData, rsa);
                }

                return rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("RSA解密失败", ex);
            }
        }

        /// <summary>
        /// 生成密钥对，根据构造函数指定的格式生成
        /// </summary>
        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create(_keySize);
                return _keyFormat switch
                {
                    "pkcs1" => (rsa.ExportRSAPublicKey(), rsa.ExportRSAPrivateKey()),
                    "pkcs8" => (rsa.ExportSubjectPublicKeyInfo(), rsa.ExportPkcs8PrivateKey()),
                    _ => throw new CryptoException($"不支持的密钥格式: {_keyFormat}")
                };
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA密钥对生成失败 (格式: {_keyFormat})", ex);
            }
        }

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            ValidateSignInput(data, privateKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, privateKey);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("RSA签名失败", ex);
            }
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public bool VerifySign(byte[] data, byte[] signature, byte[] publicKey)
        {
            ValidateVerifyInput(data, signature, publicKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, publicKey);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("RSA签名验证失败", ex);
            }
        }

        /// <summary>
        /// 异步加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey)
        {
            ValidateEncryptInput(data, publicKey);
            return await Task.Run(() => Encrypt(data, publicKey)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步解密
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            ValidateDecryptInput(encryptedData, privateKey);
            return await Task.Run(() => Decrypt(encryptedData, privateKey)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public async Task<byte[]> SignAsync(byte[] data, byte[] privateKey)
        {
            ValidateSignInput(data, privateKey);
            return await Task.Run(() => Sign(data, privateKey)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步验证签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public async Task<bool> VerifySignAsync(byte[] data, byte[] signature, byte[] publicKey)
        {
            ValidateVerifyInput(data, signature, publicKey);
            return await Task.Run(() => VerifySign(data, signature, publicKey)).ConfigureAwait(false);
        }

        /// <summary>
        /// 带取消令牌的异步加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey, CancellationToken cancellationToken)
        {
            ValidateEncryptInput(data, publicKey);
            return await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return Encrypt(data, publicKey);
            }, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// 使用指定填充模式加密
        /// </summary>
        /// <param name="data"></param>
        /// <param name="publicKey"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Encrypt(byte[] data, byte[] publicKey, AsymmetricPaddingMode paddingMode)
        {
            ValidateEncryptInput(data, publicKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, publicKey);

                var padding = CryptoPaddingUtil.GetRSAEncryptionPadding(paddingMode);
                var maxDataLength = GetMaxDataLength(rsa.KeySize, paddingMode);

                if (data.Length > maxDataLength)
                {
                    return EncryptLargeData(data, rsa, padding);
                }

                return rsa.Encrypt(data, padding);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA加密失败 (填充模式: {paddingMode})", ex);
            }
        }

        /// <summary>
        /// 使用指定填充模式解密
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="privateKey"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Decrypt(byte[] encryptedData, byte[] privateKey, AsymmetricPaddingMode paddingMode)
        {
            ValidateDecryptInput(encryptedData, privateKey);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, privateKey);

                var padding = CryptoPaddingUtil.GetRSAEncryptionPadding(paddingMode);
                var blockSize = rsa.KeySize / 8;

                if (encryptedData.Length > blockSize)
                {
                    return DecryptLargeData(encryptedData, rsa, padding);
                }

                return rsa.Decrypt(encryptedData, padding);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA解密失败 (填充模式: {paddingMode})", ex);
            }
        }

        /// <summary>
        /// 使用指定签名算法签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="privateKey"></param>
        /// <param name="signatureAlgorithm"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public byte[] Sign(byte[] data, byte[] privateKey, SignatureAlgorithm signatureAlgorithm)
        {
            ValidateSignInput(data, privateKey);

            if (!CryptoPaddingUtil.IsRSACompatible(signatureAlgorithm))
            {
                throw new CryptoException($"RSA不支持签名算法: {signatureAlgorithm}");
            }

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, privateKey);

                var (hashAlgorithm, signaturePadding) = CryptoPaddingUtil.GetRSAAlgorithm(signatureAlgorithm);
                return rsa.SignData(data, hashAlgorithm, signaturePadding);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA签名失败 (算法: {signatureAlgorithm})", ex);
            }
        }

        /// <summary>
        /// 使用指定签名算法验证签名
        /// </summary>
        /// <param name="data"></param>
        /// <param name="signature"></param>
        /// <param name="publicKey"></param>
        /// <param name="signatureAlgorithm"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        public bool VerifySign(byte[] data, byte[] signature, byte[] publicKey, SignatureAlgorithm signatureAlgorithm)
        {
            ValidateVerifyInput(data, signature, publicKey);

            if (!CryptoPaddingUtil.IsRSACompatible(signatureAlgorithm))
            {
                throw new CryptoException($"RSA不支持签名算法: {signatureAlgorithm}");
            }

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, publicKey);

                var (hashAlgorithm, signaturePadding) = CryptoPaddingUtil.GetRSAAlgorithm(signatureAlgorithm);
                return rsa.VerifyData(data, signature, hashAlgorithm, signaturePadding);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA签名验证失败 (算法: {signatureAlgorithm})", ex);
            }
        }

        /// <summary>
        /// 异步使用指定填充模式加密
        /// </summary>
        public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey, AsymmetricPaddingMode paddingMode)
        {
            ValidateEncryptInput(data, publicKey);
            return await Task.Run(() => Encrypt(data, publicKey, paddingMode)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步使用指定填充模式解密
        /// </summary>
        public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey, AsymmetricPaddingMode paddingMode)
        {
            ValidateDecryptInput(encryptedData, privateKey);
            return await Task.Run(() => Decrypt(encryptedData, privateKey, paddingMode)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步使用指定签名算法签名
        /// </summary>
        public async Task<byte[]> SignAsync(byte[] data, byte[] privateKey, SignatureAlgorithm signatureAlgorithm)
        {
            ValidateSignInput(data, privateKey);
            return await Task.Run(() => Sign(data, privateKey, signatureAlgorithm)).ConfigureAwait(false);
        }

        /// <summary>
        /// 异步使用指定签名算法验证签名
        /// </summary>
        public async Task<bool> VerifySignAsync(byte[] data, byte[] signature, byte[] publicKey, SignatureAlgorithm signatureAlgorithm)
        {
            ValidateVerifyInput(data, signature, publicKey);
            return await Task.Run(() => VerifySign(data, signature, publicKey, signatureAlgorithm)).ConfigureAwait(false);
        }

        /// <summary>
        /// 获取RSA支持的签名算法列表
        /// </summary>
        /// <returns>支持的签名算法列表</returns>
        public SignatureAlgorithm[] GetSupportedSignatureAlgorithms()
        {
            return new[]
            {
                SignatureAlgorithm.MD5withRSA,
                SignatureAlgorithm.SHA1withRSA,
                SignatureAlgorithm.SHA256withRSA,
                SignatureAlgorithm.SHA384withRSA,
                SignatureAlgorithm.SHA512withRSA,
                SignatureAlgorithm.SHA1withRSA_PSS,
                SignatureAlgorithm.SHA256withRSA_PSS,
                SignatureAlgorithm.SHA384withRSA_PSS,
                SignatureAlgorithm.SHA512withRSA_PSS
            };
        }

        /// <summary>
        /// 获取RSA支持的填充模式列表
        /// </summary>
        /// <returns>支持的填充模式列表</returns>
        public AsymmetricPaddingMode[] GetSupportedPaddingModes()
        {
            return new[]
            {
                AsymmetricPaddingMode.PKCS1,
                AsymmetricPaddingMode.OAEP,
                AsymmetricPaddingMode.PSS
            };
        }

        #region PKCS格式转换方法

        /// <summary>
        /// 将PKCS1格式公钥转换为PKCS8格式
        /// </summary>
        /// <param name="pkcs1PublicKey">PKCS1格式公钥</param>
        /// <returns>PKCS8格式公钥</returns>
        public byte[] ConvertPublicKeyFromPKCS1ToPKCS8(byte[] pkcs1PublicKey)
        {
            ValidateKeyInput(pkcs1PublicKey, "PKCS1公钥");
            try
            {
                var keyFormat = DetectRsaKeyFormatByDer(pkcs1PublicKey);
                if (keyFormat == "pkcs8")
                {
                    throw new CryptoException("提供的公钥已经是PKCS8格式，无需转换");
                }
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.ImportRSAPublicKey(pkcs1PublicKey, out _);
                return rsa.ExportSubjectPublicKeyInfo();
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("PKCS1公钥转换为PKCS8格式失败", ex);
            }
        }

        /// <summary>
        /// 将PKCS8格式公钥转换为PKCS1格式
        /// </summary>
        /// <param name="pkcs8PublicKey">PKCS8格式公钥</param>
        /// <returns>PKCS1格式公钥</returns>
        public byte[] ConvertPublicKeyFromPKCS8ToPKCS1(byte[] pkcs8PublicKey)
        {
            ValidateKeyInput(pkcs8PublicKey, "PKCS8公钥");

            try
            {
                var keyFormat = DetectRsaKeyFormatByDer(pkcs8PublicKey);
                if (keyFormat == "pkcs1")
                {
                    throw new CryptoException("提供的公钥已经是PKCS1格式，无需转换");
                }
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(pkcs8PublicKey, out _);
                return rsa.ExportRSAPublicKey();
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("PKCS8公钥转换为PKCS1格式失败", ex);
            }
        }

        /// <summary>
        /// 将PKCS1格式私钥转换为PKCS8格式
        /// </summary>
        /// <param name="pkcs1PrivateKey">PKCS1格式私钥</param>
        /// <returns>PKCS8格式私钥</returns>
        public byte[] ConvertPrivateKeyFromPKCS1ToPKCS8(byte[] pkcs1PrivateKey)
        {
            ValidateKeyInput(pkcs1PrivateKey, "PKCS1私钥");

            try
            {
                var keyFormat = DetectRsaKeyFormatByDer(pkcs1PrivateKey);
                if (keyFormat == "pkcs8")
                {
                    throw new CryptoException("提供的私钥已经是PKCS8格式，无需转换");
                }
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.ImportRSAPrivateKey(pkcs1PrivateKey, out _);
                return rsa.ExportPkcs8PrivateKey();
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("PKCS1私钥转换为PKCS8格式失败", ex);
            }
        }

        /// <summary>
        /// 将PKCS8格式私钥转换为PKCS1格式
        /// </summary>
        /// <param name="pkcs8PrivateKey">PKCS8格式私钥</param>
        /// <returns>PKCS1格式私钥</returns>
        public byte[] ConvertPrivateKeyFromPKCS8ToPKCS1(byte[] pkcs8PrivateKey)
        {
            ValidateKeyInput(pkcs8PrivateKey, "PKCS8私钥");

            try
            {
                var keyFormat = DetectRsaKeyFormatByDer(pkcs8PrivateKey);
                if (keyFormat == "pkcs1")
                {
                    throw new CryptoException("提供的私钥已经是PKCS1格式，无需转换");
                }
                using var rsa = System.Security.Cryptography.RSA.Create();
                rsa.ImportPkcs8PrivateKey(pkcs8PrivateKey, out _);
                return rsa.ExportRSAPrivateKey();
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("PKCS8私钥转换为PKCS1格式失败", ex);
            }
        }

        #endregion

        #region PEM格式密钥方法

        /// <summary>
        /// 生成密钥对并返回PEM格式
        /// </summary>
        /// <returns>PEM格式的密钥对 (PublicKeyPem, PrivateKeyPem)</returns>
        public (string PublicKeyPem, string PrivateKeyPem) GenerateKeyPairPem()
        {
            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create(_keySize);

                string publicKeyPem;
                string privateKeyPem;

                switch (_keyFormat)
                {
                    case "pkcs1":
                        publicKeyPem = ConvertToPem(rsa.ExportRSAPublicKey(), "RSA PUBLIC KEY");
                        privateKeyPem = ConvertToPem(rsa.ExportRSAPrivateKey(), "RSA PRIVATE KEY");
                        break;
                    case "pkcs8":
                        publicKeyPem = ConvertToPem(rsa.ExportSubjectPublicKeyInfo(), "PUBLIC KEY");
                        privateKeyPem = ConvertToPem(rsa.ExportPkcs8PrivateKey(), "PRIVATE KEY");
                        break;
                    default:
                        throw new CryptoException($"不支持的密钥格式: {_keyFormat}");
                }

                return (publicKeyPem, privateKeyPem);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException($"RSA密钥对PEM格式生成失败 (格式: {_keyFormat})", ex);
            }
        }

        /// <summary>
        /// 导出公钥为PEM格式
        /// </summary>
        /// <param name="publicKey">公钥字节数组</param>
        /// <returns>PEM格式公钥</returns>
        public string ExportPublicKeyToPem(byte[] publicKey)
        {
            ValidateKeyInput(publicKey, "公钥");

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, publicKey);

                return ExportPublicKeyPem(rsa);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("导出公钥为PEM格式失败", ex);
            }
        }

        /// <summary>
        /// 导出私钥为PEM格式
        /// </summary>
        /// <param name="privateKey">私钥字节数组</param>
        /// <returns>PEM格式私钥</returns>
        public string ExportPrivateKeyToPem(byte[] privateKey)
        {
            ValidateKeyInput(privateKey, "私钥");

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, privateKey);

                return ExportPrivateKeyPem(rsa);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("导出私钥为PEM格式失败", ex);
            }
        }

        /// <summary>
        /// 从PEM格式导入公钥
        /// </summary>
        /// <param name="publicKeyPem">PEM格式公钥</param>
        /// <returns>公钥字节数组</returns>
        public byte[] ImportPublicKeyFromPem(string publicKeyPem)
        {
            ValidateStringInput(publicKeyPem, "PEM格式公钥");

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKeyFromPemString(rsa, publicKeyPem);

                return ExportPublicKey(rsa);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("从PEM格式导入公钥失败", ex);
            }
        }

        /// <summary>
        /// 从PEM格式导入私钥
        /// </summary>
        /// <param name="privateKeyPem">PEM格式私钥</param>
        /// <returns>私钥字节数组</returns>
        public byte[] ImportPrivateKeyFromPem(string privateKeyPem)
        {
            ValidateStringInput(privateKeyPem, "PEM格式私钥");

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKeyFromPemString(rsa, privateKeyPem);

                return ExportPrivateKey(rsa);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("从PEM格式导入私钥失败", ex);
            }
        }

        /// <summary>
        /// 使用PEM格式公钥加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKeyPem">PEM格式公钥</param>
        /// <returns>加密后的数据</returns>
        public byte[] EncryptWithPem(byte[] data, string publicKeyPem)
        {
            ValidateEncryptInput(data, publicKeyPem);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKeyFromPemString(rsa, publicKeyPem);

                var maxDataLength = GetMaxDataLength(rsa.KeySize);
                if (data.Length > maxDataLength)
                {
                    return EncryptLargeData(data, rsa);
                }

                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("使用PEM公钥加密失败", ex);
            }
        }

        /// <summary>
        /// 使用PEM格式私钥解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKeyPem">PEM格式私钥</param>
        /// <returns>解密后的数据</returns>
        public byte[] DecryptWithPem(byte[] encryptedData, string privateKeyPem)
        {
            ValidateDecryptInput(encryptedData, privateKeyPem);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKeyFromPemString(rsa, privateKeyPem);

                var blockSize = rsa.KeySize / 8;
                if (encryptedData.Length > blockSize)
                {
                    return DecryptLargeData(encryptedData, rsa);
                }

                return rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("使用PEM私钥解密失败", ex);
            }
        }

        /// <summary>
        /// 使用PEM格式私钥签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKeyPem">PEM格式私钥</param>
        /// <returns>签名</returns>
        public byte[] SignWithPem(byte[] data, string privateKeyPem)
        {
            ValidateSignInput(data, privateKeyPem);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKeyFromPemString(rsa, privateKeyPem);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("使用PEM私钥签名失败", ex);
            }
        }

        /// <summary>
        /// 使用PEM格式公钥验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKeyPem">PEM格式公钥</param>
        /// <returns>验证结果</returns>
        public bool VerifySignWithPem(byte[] data, byte[] signature, string publicKeyPem)
        {
            ValidateVerifyInput(data, signature, publicKeyPem);

            try
            {
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKeyFromPemString(rsa, publicKeyPem);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("使用PEM公钥验证签名失败", ex);
            }
        }

        /// <summary>
        /// 将字节数组转换为PEM格式
        /// </summary>
        /// <param name="keyBytes">密钥字节数组</param>
        /// <param name="keyType">密钥类型标识</param>
        /// <returns>PEM格式字符串</returns>
        private static string ConvertToPem(byte[] keyBytes, string keyType)
        {
            var base64 = Convert.ToBase64String(keyBytes);
            var sb = new StringBuilder();

            sb.AppendLine($"-----BEGIN {keyType}-----");

            // 每行64个字符分割
            for (var i = 0; i < base64.Length; i += 64)
            {
                sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
            }

            sb.AppendLine($"-----END {keyType}-----");

            return sb.ToString();
        }

        /// <summary>
        /// 从PEM格式字符串中提取密钥字节
        /// </summary>
        /// <param name="pemKey">PEM格式密钥</param>
        /// <returns>密钥字节数组</returns>
        private static byte[] ExtractKeyBytesFromPem(string pemKey)
        {
            var lines = pemKey.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var base64Data = new StringBuilder();

            bool inKey = false;
            foreach (var line in lines)
            {
                if (line.StartsWith("-----BEGIN"))
                {
                    inKey = true;
                    continue;
                }
                if (line.StartsWith("-----END"))
                {
                    break;
                }
                if (inKey)
                {
                    base64Data.Append(line.Trim());
                }
            }

            return Convert.FromBase64String(base64Data.ToString());
        }

        /// <summary>
        /// 从PEM格式字符串导入私钥
        /// </summary>
        /// <param name="rsa">RSA实例</param>
        /// <param name="pemKey">PEM格式私钥</param>
        private void ImportPrivateKeyFromPemString(System.Security.Cryptography.RSA rsa, string pemKey)
        {
            var keyBytes = ExtractKeyBytesFromPem(pemKey);

            if (pemKey.Contains("RSA PRIVATE KEY")) // PKCS#1格式
            {
                rsa.ImportRSAPrivateKey(keyBytes, out _);
            }
            else if (pemKey.Contains("PRIVATE KEY")) // PKCS#8格式
            {
                rsa.ImportPkcs8PrivateKey(keyBytes, out _);
            }
            else
            {
                throw new CryptoException("无法识别的PEM私钥格式");
            }
        }

        /// <summary>
        /// 从PEM格式字符串导入公钥
        /// </summary>
        /// <param name="rsa">RSA实例</param>
        /// <param name="pemKey">PEM格式公钥</param>
        private void ImportPublicKeyFromPemString(System.Security.Cryptography.RSA rsa, string pemKey)
        {
            var keyBytes = ExtractKeyBytesFromPem(pemKey);

            if (pemKey.Contains("RSA PUBLIC KEY")) // PKCS#1格式
            {
                rsa.ImportRSAPublicKey(keyBytes, out _);
            }
            else if (pemKey.Contains("PUBLIC KEY")) // X.509/PKCS#8格式
            {
                rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);
            }
            else
            {
                throw new CryptoException("无法识别的PEM公钥格式");
            }
        }

        #endregion

        #region ASN.1 分析 - 判断 PKCS#1 / PKCS#8

        /// <summary>
        /// 通过分析 ASN.1/DER 二进制结构判断 RSA 密钥是 PKCS#1 还是 PKCS#8。
        /// 注意：这里的 keyData 必须是 DER（二进制）数据；若为 PEM 请先去掉头尾并 Base64 解码。
        /// </summary>
        /// <param name="keyData">DER 格式的密钥字节数组</param>
        /// <returns>"pkcs1" 或 "pkcs8"</returns>
        /// <exception cref="CryptoException">当结构非法或无法判断时抛出</exception>
        public static string DetectRsaKeyFormatByDer(byte[] keyData)
        {
            ValidateKeyInput(keyData, "密钥");

            int offset = 0;

            // 顶层必须是 SEQUENCE (0x30)
            if (keyData.Length < 2 || keyData[offset] != 0x30)
                throw new CryptoException("无效的 ASN.1/DER：顶层不是 SEQUENCE。");

            // 跳过顶层 SEQUENCE 的 tag
            offset++;

            // 读取顶层长度
            int topContentLen = Asn1ReadLength(keyData, ref offset);
            int topEnd = offset + topContentLen;
            if (topEnd > keyData.Length)
                throw new CryptoException("ASN.1 数据不完整。");

            if (offset >= topEnd)
                throw new CryptoException("ASN.1 SEQUENCE 为空。");

            // 第一个子元素的 tag
            byte firstTag = keyData[offset];

            // 规则：
            // - PKCS#8 公钥 (SubjectPublicKeyInfo):
            //     顶层第一个子元素是 AlgorithmIdentifier -> SEQUENCE (0x30)
            // - PKCS#1（公钥/私钥）：

            //     顶层第一个子元素是 INTEGER (0x02)
            // - PKCS#8 私钥 (PrivateKeyInfo):
            //     顶层第一个子元素是 version -> INTEGER (0x02)
            //     但第二个子元素是 AlgorithmIdentifier -> SEQUENCE (0x30)
            if (firstTag == 0x30)
            {
                // 顶层子元素一上来就是 SEQUENCE，判定为 PKCS#8（通常是公钥 SPKI）
                return "pkcs8";
            }

            if (firstTag == 0x02)
            {
                // 跳过第一个 INTEGER（可能是 RSAPrivateKey 的 version 或 RSAPublicKey/PrivateKey 的第一个参数）
                Asn1Skip(keyData, ref offset);

                if (offset >= topEnd)
                {
                    // 只存在一个 INTEGER，结构异常但更接近 PKCS#1
                    return "pkcs1";
                }

                // 查看第二个子元素
                byte secondTag = keyData[offset];

                if (secondTag == 0x30)
                {
                    // INTEGER (version) 后是 SEQUENCE (AlgorithmIdentifier) -> PKCS#8 私钥
                    return "pkcs8";
                }

                // 否则通常仍为 INTEGER（模数/指数等）-> PKCS#1
                return "pkcs1";
            }

            throw new CryptoException($"无法识别的 ASN.1 结构(Tag=0x{firstTag:X2})，无法判断为 PKCS#1 或 PKCS#8。");
        }

        /// <summary>
        /// 从 PEM 字符串中判断 RSA 密钥格式（内部会提取 DER 后调用二进制结构分析）。
        /// </summary>
        public static string DetectRsaKeyFormatFromPem(string pem)
        {
            ValidateStringInput(pem, "PEM 格式密钥");
            var der = ExtractKeyBytesFromPem(pem);
            return DetectRsaKeyFormatByDer(der);
        }

        /// <summary>
        /// 读取 ASN.1 长度（支持短/长格式）。offset 需指向长度首字节，返回内容长度，并将 offset 前移到内容起始位置。
        /// </summary>
        private static int Asn1ReadLength(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
                throw new CryptoException("ASN.1 长度字段越界。");

            byte b = data[offset++];
            if ((b & 0x80) == 0)
            {
                // 短格式
                return b;
            }

            int count = b & 0x7F;
            if (count == 0 || count > 4)
                throw new CryptoException("不支持的 ASN.1 长度编码。");

            if (offset + count > data.Length)
                throw new CryptoException("ASN.1 长度字段越界。");

            int len = 0;
            for (int i = 0; i < count; i++)
            {
                len = (len << 8) | data[offset++];
            }

            return len;
        }

        /// <summary>
        /// 跳过一个完整的 ASN.1 元素（Tag + Length + Value）。offset 需指向元素 Tag。
        /// </summary>
        private static void Asn1Skip(byte[] data, ref int offset)
        {
            if (offset >= data.Length)
                throw new CryptoException("ASN.1 元素越界。");

            // 跳过 tag
            offset++;

            // 读取长度，offset 将移动到内容起始
            int len = Asn1ReadLength(data, ref offset);

            // 跳过内容
            int end = offset + len;
            if (end > data.Length)
                throw new CryptoException("ASN.1 元素内容越界。");

            offset = end;
        }

        #endregion

        #region 私有辅助方法

        /// <summary>
        /// 导出pem格式公钥，自动检测格式
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        private string ExportPublicKeyPem(System.Security.Cryptography.RSA rsa)
        {
            return _keyFormat switch
            {
                "pkcs1" => ConvertToPem(rsa.ExportRSAPublicKey(), "RSA PUBLIC KEY"),
                "pkcs8" => ConvertToPem(rsa.ExportSubjectPublicKeyInfo(), "PUBLIC KEY"),
                _ => throw new CryptoException($"不支持的密钥格式: {_keyFormat}")
            };
        }

        /// <summary>
        /// 导出pem格式私钥，自动检测格式
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        private string ExportPrivateKeyPem(System.Security.Cryptography.RSA rsa)
        {
            return _keyFormat switch
            {
                "pkcs1" => ConvertToPem(rsa.ExportRSAPrivateKey(), "RSA PRIVATE KEY"),
                "pkcs8" => ConvertToPem(rsa.ExportPkcs8PrivateKey(), "PRIVATE KEY"),
                _ => throw new CryptoException($"不支持的密钥格式: {_keyFormat}")
            };
        }

        /// <summary>
        /// 导出私钥，自动检测格式
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        private byte[] ExportPrivateKey(System.Security.Cryptography.RSA rsa)
        {
            return _keyFormat switch
            {
                "pkcs1" => rsa.ExportRSAPrivateKey(),
                "pkcs8" => rsa.ExportPkcs8PrivateKey(),
                _ => throw new CryptoException($"不支持的密钥格式: {_keyFormat}")
            };
        }

        /// <summary>
        /// 导出公钥，自动检测格式
        /// </summary>
        /// <param name="rsa"></param>
        /// <returns></returns>
        /// <exception cref="CryptoException"></exception>
        private byte[] ExportPublicKey(System.Security.Cryptography.RSA rsa)
        {
            return _keyFormat switch
            {
                "pkcs1" => rsa.ExportRSAPublicKey(),
                "pkcs8" => rsa.ExportSubjectPublicKeyInfo(),
                _ => throw new CryptoException($"不支持的密钥格式: {_keyFormat}")
            };
        }

        /// <summary>
        /// 智能导入RSA公钥，自动检测格式
        /// </summary>
        /// <param name="rsa">RSA实例</param>
        /// <param name="publicKey">公钥数据</param>
        private void ImportPublicKey(System.Security.Cryptography.RSA rsa, byte[] publicKey)
        {
            switch (_keyFormat)
            {
                case "pkcs1":
                    rsa.ImportRSAPublicKey(publicKey, out _);
                    break;
                case "pkcs8":
                    rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                    break;
                default:
                    throw new CryptoException("无法导入公钥，不支持的密钥格式");
            }
        }

        /// <summary>
        /// 智能导入RSA私钥，自动检测格式
        /// </summary>
        /// <param name="rsa">RSA实例</param>
        /// <param name="privateKey">私钥数据</param>
        private void ImportPrivateKey(System.Security.Cryptography.RSA rsa, byte[] privateKey)
        {
            switch (_keyFormat)
            {
                case "pkcs1":
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    break;
                case "pkcs8":
                    rsa.ImportPkcs8PrivateKey(privateKey, out _);
                    break;
                default:
                    throw new CryptoException("无法导入私钥，不支持的密钥格式");
            }
        }

        private void ValidateKeySize(int keySize)
        {
            if (keySize < 1024 || keySize % 8 != 0)
                throw new ArgumentException("密钥长度必须大于等于1024位且为8的倍数", nameof(keySize));
        }

        private static void ValidateKeyFormat(string keyFormat)
        {
            if (string.IsNullOrWhiteSpace(keyFormat))
                throw new ArgumentException("密钥格式不能为空", nameof(keyFormat));

            var format = keyFormat.ToLower();
            if (format != "pkcs1" && format != "pkcs8")
                throw new ArgumentException("密钥格式只支持 'pkcs1' 或 'pkcs8'", nameof(keyFormat));
        }

        private static void ValidateEncryptInput(byte[] data, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待加密数据不能为空");
            if (publicKey == null || publicKey.Length == 0)
                throw new KeyException("公钥不能为空");
        }

        private static void ValidateDecryptInput(byte[] encryptedData, byte[] privateKey)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new DataException("待解密数据不能为空");
            if (privateKey == null || privateKey.Length == 0)
                throw new KeyException("私钥不能为空");
        }

        private static void ValidateSignInput(byte[] data, byte[] privateKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待签名数据不能为空");
            if (privateKey == null || privateKey.Length == 0)
                throw new KeyException("私钥不能为空");
        }

        private static void ValidateVerifyInput(byte[] data, byte[] signature, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("原始数据不能为空");
            if (signature == null || signature.Length == 0)
                throw new DataException("签名数据不能为空");
            if (publicKey == null || publicKey.Length == 0)
                throw new KeyException("公钥不能为空");
        }

        // PEM格式密钥验证方法重载
        private static void ValidateEncryptInput(byte[] data, string publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待加密数据不能为空");
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new KeyException("公钥不能为空");
        }

        private static void ValidateDecryptInput(byte[] encryptedData, string privateKey)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new DataException("待解密数据不能为空");
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new KeyException("私钥不能为空");
        }

        private static void ValidateSignInput(byte[] data, string privateKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待签名数据不能为空");
            if (string.IsNullOrWhiteSpace(privateKey))
                throw new KeyException("私钥不能为空");
        }

        private static void ValidateVerifyInput(byte[] data, byte[] signature, string publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("原始数据不能为空");
            if (signature == null || signature.Length == 0)
                throw new DataException("签名数据不能为空");
            if (string.IsNullOrWhiteSpace(publicKey))
                throw new KeyException("公钥不能为空");
        }

        private static void ValidateKeyInput(byte[] keyData, string keyType)
        {
            if (keyData == null || keyData.Length == 0)
                throw new KeyException($"{keyType}不能为空");
        }

        private static void ValidateStringInput(string input, string inputType)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException($"{inputType}不能为空", nameof(input));
        }

        /// <summary>
        /// 获取最大可加密数据长度，固定PKCS1填充模式
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        private static int GetMaxDataLength(int keySize)
        {
            return (keySize / 8) - PKCS1_PADDING_SIZE;
        }

        /// <summary>
        /// 获取最大可加密数据长度，支持多种填充模式
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        private static int GetMaxDataLength(int keySize, AsymmetricPaddingMode paddingMode)
        {
            return paddingMode switch
            {
                AsymmetricPaddingMode.PKCS1 => (keySize / 8) - PKCS1_PADDING_SIZE,
                AsymmetricPaddingMode.OAEP => (keySize / 8) - 42, // OAEP-SHA1 需要42字节填充
                _ => (keySize / 8) - PKCS1_PADDING_SIZE
            };
        }

        /// <summary>
        /// 获取最大可加密数据长度，支持多种填充模式
        /// </summary>
        /// <param name="keySize"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        private static int GetMaxDataLength(int keySize, RSAEncryptionPadding padding)
        {
            if (padding == RSAEncryptionPadding.Pkcs1)
                return (keySize / 8) - PKCS1_PADDING_SIZE;
            else if (padding == RSAEncryptionPadding.OaepSHA1)
                return (keySize / 8) - 42;
            else if (padding == RSAEncryptionPadding.OaepSHA256)
                return (keySize / 8) - 66;
            else if (padding == RSAEncryptionPadding.OaepSHA384)
                return (keySize / 8) - 98;
            else if (padding == RSAEncryptionPadding.OaepSHA512)
                return (keySize / 8) - 130;
            else
                return (keySize / 8) - PKCS1_PADDING_SIZE;
        }

        /// <summary>
        /// 分块加密 - 固定PKCS1填充模式
        /// </summary>
        /// <param name="data"></param>
        /// <param name="rsa"></param>
        /// <returns></returns>
        private byte[] EncryptLargeData(byte[] data, System.Security.Cryptography.RSA rsa)
        {
            var blockSize = GetMaxDataLength(rsa.KeySize);
            var encryptedBlocks = new List<byte[]>();
            var totalLength = 0;

            var dataSpan = data.AsSpan();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, data.Length - i);
                var block = dataSpan.Slice(i, currentBlockSize).ToArray();
                var encryptedBlock = rsa.Encrypt(block, RSAEncryptionPadding.Pkcs1); // 固定填充模式为PKCS1
                encryptedBlocks.Add(encryptedBlock);
                totalLength += encryptedBlock.Length;
            }

            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in encryptedBlocks)
            {
                Buffer.BlockCopy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }

        /// <summary>
        /// 分块加密，支持指定填充模式
        /// </summary>
        /// <param name="data"></param>
        /// <param name="rsa"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        private byte[] EncryptLargeData(byte[] data, System.Security.Cryptography.RSA rsa, RSAEncryptionPadding padding)
        {
            var blockSize = GetMaxDataLength(rsa.KeySize, padding);
            var encryptedBlocks = new System.Collections.Generic.List<byte[]>();
            var totalLength = 0;

            var dataSpan = data.AsSpan();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, data.Length - i);
                var block = dataSpan.Slice(i, currentBlockSize).ToArray();
                var encryptedBlock = rsa.Encrypt(block, padding);
                encryptedBlocks.Add(encryptedBlock);
                totalLength += encryptedBlock.Length;
            }

            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in encryptedBlocks)
            {
                Buffer.BlockCopy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }

        /// <summary>
        /// 优化的分块解密
        /// </summary>
        private byte[] DecryptLargeData(byte[] encryptedData, System.Security.Cryptography.RSA rsa)
        {
            var blockSize = rsa.KeySize / 8;
            var decryptedBlocks = new System.Collections.Generic.List<byte[]>();
            var totalLength = 0;

            var dataSpan = encryptedData.AsSpan();
            for (int i = 0; i < encryptedData.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, encryptedData.Length - i);
                var block = dataSpan.Slice(i, currentBlockSize).ToArray();
                var decryptedBlock = rsa.Decrypt(block, RSAEncryptionPadding.Pkcs1);
                decryptedBlocks.Add(decryptedBlock);
                totalLength += decryptedBlock.Length;
            }

            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in decryptedBlocks)
            {
                Buffer.BlockCopy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }

        /// <summary>
        /// 优化的分块解密 - 支持指定填充模式
        /// </summary>
        private byte[] DecryptLargeData(byte[] encryptedData, System.Security.Cryptography.RSA rsa, RSAEncryptionPadding padding)
        {
            var blockSize = rsa.KeySize / 8;
            var decryptedBlocks = new System.Collections.Generic.List<byte[]>();
            var totalLength = 0;

            var dataSpan = encryptedData.AsSpan();
            for (int i = 0; i < encryptedData.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, encryptedData.Length - i);
                var block = dataSpan.Slice(i, currentBlockSize).ToArray();
                var decryptedBlock = rsa.Decrypt(block, padding);
                decryptedBlocks.Add(decryptedBlock);
                totalLength += decryptedBlock.Length;
            }

            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in decryptedBlocks)
            {
                Buffer.BlockCopy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }

        #endregion
    }
}
