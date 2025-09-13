using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using CryptoTool.Algorithm.Interfaces;
using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Utils;

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

        /// <summary>
        /// 初始化RSA加密算法
        /// </summary>
        /// <param name="keySize">密钥长度，默认2048位</param>
        public RsaCrypto(int keySize = 2048)
        {
            if (keySize < 1024 || keySize % 8 != 0)
                throw new ArgumentException("密钥长度必须大于等于1024位且为8的倍数", nameof(keySize));

            _keySize = keySize;
        }

        /// <summary>
        /// 加密
        /// </summary>
        public byte[] Encrypt(byte[] data, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待加密数据不能为空");

            if (publicKey == null || publicKey.Length == 0)
                throw new KeyException("公钥不能为空");

            try
            {
                using (var rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportRSAPublicKey(publicKey, out _);
                    
                    // RSA加密有长度限制，需要分块处理
                    var maxDataLength = (rsa.KeySize / 8) - 42; // PKCS1填充需要42字节
                    if (data.Length > maxDataLength)
                    {
                        return EncryptLargeData(data, rsa);
                    }

                    return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("RSA加密失败", ex);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData, byte[] privateKey)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new DataException("待解密数据不能为空");

            if (privateKey == null || privateKey.Length == 0)
                throw new KeyException("私钥不能为空");

            try
            {
                using (var rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    
                    // 检查是否需要分块解密
                    var blockSize = rsa.KeySize / 8;
                    if (encryptedData.Length > blockSize)
                    {
                        return DecryptLargeData(encryptedData, rsa);
                    }

                    return rsa.Decrypt(encryptedData, RSAEncryptionPadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("RSA解密失败", ex);
            }
        }

        /// <summary>
        /// 生成密钥对
        /// </summary>
        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            try
            {
                using (var rsa = System.Security.Cryptography.RSA.Create(_keySize))
                {
                    var publicKey = rsa.ExportRSAPublicKey();
                    var privateKey = rsa.ExportRSAPrivateKey();
                    return (publicKey, privateKey);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("RSA密钥对生成失败", ex);
            }
        }

        /// <summary>
        /// 签名
        /// </summary>
        public byte[] Sign(byte[] data, byte[] privateKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待签名数据不能为空");

            if (privateKey == null || privateKey.Length == 0)
                throw new KeyException("私钥不能为空");

            try
            {
                using (var rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportRSAPrivateKey(privateKey, out _);
                    return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("RSA签名失败", ex);
            }
        }

        /// <summary>
        /// 验证签名
        /// </summary>
        public bool VerifySign(byte[] data, byte[] signature, byte[] publicKey)
        {
            if (data == null || data.Length == 0)
                throw new DataException("原始数据不能为空");

            if (signature == null || signature.Length == 0)
                throw new DataException("签名数据不能为空");

            if (publicKey == null || publicKey.Length == 0)
                throw new KeyException("公钥不能为空");

            try
            {
                using (var rsa = System.Security.Cryptography.RSA.Create())
                {
                    rsa.ImportRSAPublicKey(publicKey, out _);
                    return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {
                throw new CryptoException("RSA签名验证失败", ex);
            }
        }

        /// <summary>
        /// 异步加密
        /// </summary>
        public async Task<byte[]> EncryptAsync(byte[] data, byte[] publicKey)
        {
            return await Task.Run(() => Encrypt(data, publicKey));
        }

        /// <summary>
        /// 异步解密
        /// </summary>
        public async Task<byte[]> DecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            return await Task.Run(() => Decrypt(encryptedData, privateKey));
        }

        /// <summary>
        /// 异步签名
        /// </summary>
        public async Task<byte[]> SignAsync(byte[] data, byte[] privateKey)
        {
            return await Task.Run(() => Sign(data, privateKey));
        }

        /// <summary>
        /// 异步验证签名
        /// </summary>
        public async Task<bool> VerifySignAsync(byte[] data, byte[] signature, byte[] publicKey)
        {
            return await Task.Run(() => VerifySign(data, signature, publicKey));
        }

        /// <summary>
        /// 分块加密大数据
        /// </summary>
        private byte[] EncryptLargeData(byte[] data, System.Security.Cryptography.RSA rsa)
        {
            var blockSize = (rsa.KeySize / 8) - 42; // PKCS1填充需要42字节
            var encryptedBlocks = new System.Collections.Generic.List<byte[]>();

            for (int i = 0; i < data.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, data.Length - i);
                var block = new byte[currentBlockSize];
                Array.Copy(data, i, block, 0, currentBlockSize);
                encryptedBlocks.Add(rsa.Encrypt(block, RSAEncryptionPadding.Pkcs1));
            }

            // 计算总长度
            var totalLength = 0;
            foreach (var block in encryptedBlocks)
            {
                totalLength += block.Length;
            }

            // 合并所有加密块
            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in encryptedBlocks)
            {
                Array.Copy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }

        /// <summary>
        /// 分块解密大数据
        /// </summary>
        private byte[] DecryptLargeData(byte[] encryptedData, System.Security.Cryptography.RSA rsa)
        {
            var blockSize = rsa.KeySize / 8;
            var decryptedBlocks = new System.Collections.Generic.List<byte[]>();

            for (int i = 0; i < encryptedData.Length; i += blockSize)
            {
                var currentBlockSize = Math.Min(blockSize, encryptedData.Length - i);
                var block = new byte[currentBlockSize];
                Array.Copy(encryptedData, i, block, 0, currentBlockSize);
                decryptedBlocks.Add(rsa.Decrypt(block, RSAEncryptionPadding.Pkcs1));
            }

            // 计算总长度
            var totalLength = 0;
            foreach (var block in decryptedBlocks)
            {
                totalLength += block.Length;
            }

            // 合并所有解密块
            var result = new byte[totalLength];
            var offset = 0;
            foreach (var block in decryptedBlocks)
            {
                Array.Copy(block, 0, result, offset, block.Length);
                offset += block.Length;
            }

            return result;
        }
    }
}
