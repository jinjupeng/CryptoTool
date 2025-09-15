using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Interfaces;
using CryptoTool.Algorithm.Utils;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
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
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, pkcs1PublicKey);
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
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPublicKey(rsa, pkcs8PublicKey);
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
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, pkcs1PrivateKey);
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
                using var rsa = System.Security.Cryptography.RSA.Create();
                ImportPrivateKey(rsa, pkcs8PrivateKey);
                return rsa.ExportRSAPrivateKey();
            }
            catch (Exception ex) when (!(ex is CryptoException))
            {
                throw new CryptoException("PKCS8私钥转换为PKCS1格式失败", ex);
            }
        }


        #endregion

        #region 私有辅助方法

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

        private static void ValidateKeyInput(byte[] keyData, string keyType)
        {
            if (keyData == null || keyData.Length == 0)
                throw new KeyException($"{keyType}不能为空");
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
