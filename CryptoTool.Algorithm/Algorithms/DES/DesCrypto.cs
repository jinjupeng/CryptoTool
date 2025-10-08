using CryptoTool.Algorithm.Exceptions;
using CryptoTool.Algorithm.Interfaces;
using CryptoTool.Algorithm.Utils;
using System;
using System.Security.Cryptography;

namespace CryptoTool.Algorithm.Algorithms.DES
{
    /// <summary>
    /// DES加密算法实现
    /// </summary>
    public class DesCrypto : ISymmetricCrypto
    {
        public string AlgorithmName => "DES";
        public CryptoAlgorithmType AlgorithmType => CryptoAlgorithmType.Symmetric;

        // DES算法常量
        private const int DES_KEY_SIZE_BYTES = 8;        // DES密钥长度（字节）
        private const int DES_IV_SIZE_BYTES = 8;         // DES IV长度（字节）
        private const int DES_KEY_BITS = 64;         // DES密钥位数
        private const int DES_BLOCK_BITS = 64;       // DES块位数

        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;

        /// <summary>
        /// 初始化DES加密算法
        /// </summary>
        /// <param name="mode">加密模式，默认CBC</param>
        /// <param name="padding">填充模式，默认PKCS7</param>
        public DesCrypto(CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7)
        {
            _mode = mode;
            _padding = padding;
        }

        /// <summary>
        /// 加密
        /// </summary>
        public byte[] Encrypt(byte[] data, byte[] key, byte[]? iv = null)
        {
            // 参数验证
            ValidateEncryptParameters(data, key, iv);

            try
            {
                using var des = System.Security.Cryptography.DES.Create();
                des.Mode = _mode;
                des.Padding = _padding;
                des.Key = key;

                // ECB模式不需要IV
                if (IsECBMode && iv != null)
                {
                    throw new KeyException("ECB模式不支持IV参数");
                }
                else
                {
                     if (iv != null)
                     {
                         if (iv.Length != DES_IV_SIZE_BYTES)
                             throw new KeyException($"IV长度必须为{DES_IV_SIZE_BYTES}字节");
                         des.IV = iv;
                     }
                    else
                    {
                        des.GenerateIV();
                    }
                }

                using var encryptor = des.CreateEncryptor();
                var encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);

                // 如果IV是自动生成的，需要将IV和加密数据一起返回（ECB模式除外）
                if (iv == null && _mode != CipherMode.ECB)
                {
                    var result = new byte[des.IV.Length + encrypted.Length];
                    Array.Copy(des.IV, 0, result, 0, des.IV.Length);
                    Array.Copy(encrypted, 0, result, des.IV.Length, encrypted.Length);
                    return result;
                }

                return encrypted;
            }
            catch (Exception ex)
            {
                throw new CryptoException("DES加密失败", ex);
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        public byte[] Decrypt(byte[] encryptedData, byte[] key, byte[]? iv = null)
        {
            // 参数验证
            ValidateDecryptParameters(encryptedData, key, iv);

            try
            {
                using var des = System.Security.Cryptography.DES.Create();
                des.Mode = _mode;
                des.Padding = _padding;
                des.Key = key;

                // ECB模式不需要IV
                if (IsECBMode && iv != null)
                {
                    throw new KeyException("ECB模式不支持IV参数");
                }
                else
                {
                    // 如果IV为null，说明IV包含在加密数据的前面
                     if (iv == null)
                     {
                         if (encryptedData.Length < DES_IV_SIZE_BYTES)
                             throw new DataException("加密数据长度不足，无法提取IV");

                         var extractedIV = new byte[DES_IV_SIZE_BYTES];
                         Array.Copy(encryptedData, 0, extractedIV, 0, extractedIV.Length);
                         des.IV = extractedIV;

                         var actualEncryptedData = new byte[encryptedData.Length - extractedIV.Length];
                         Array.Copy(encryptedData, extractedIV.Length, actualEncryptedData, 0, actualEncryptedData.Length);
                         encryptedData = actualEncryptedData;
                     }
                     else
                     {
                         if (iv.Length != DES_IV_SIZE_BYTES)
                             throw new KeyException($"IV长度必须为{DES_IV_SIZE_BYTES}字节");
                         des.IV = iv;
                     }
                }

                using var decryptor = des.CreateDecryptor();
                return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
            }
            catch (Exception ex)
            {
                throw new CryptoException("DES解密失败", ex);
            }
        }

        /// <summary>
        /// 生成随机密钥
        /// </summary>
        /// <returns>随机密钥</returns>
        public byte[] GenerateKey()
        {
            return StringUtil.GenerateRandomKey(DES_KEY_BITS); // DES密钥为64位
        }

        /// <summary>
        /// 生成随机IV
        /// </summary>
        /// <returns>随机IV</returns>
        public byte[] GenerateIV()
        {
            return StringUtil.GenerateRandomIV(DES_BLOCK_BITS); // DES块大小为64位
        }

        /// <summary>
        /// 从密码生成密钥（使用PBKDF2）
        /// </summary>
        /// <param name="password">密码</param>
        /// <param name="salt">盐值</param>
        /// <param name="iterations">迭代次数</param>
        /// <returns>生成的密钥</returns>
        public byte[] DeriveKeyFromPassword(string password, byte[] salt, int iterations = 10000)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("密码不能为空", nameof(password));

            if (salt == null || salt.Length == 0)
                throw new ArgumentException("盐值不能为空", nameof(salt));

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA1);
            return pbkdf2.GetBytes(DES_KEY_SIZE_BYTES); // DES密钥为8字节
        }

        /// <summary>
        /// 从密码生成密钥（使用PBKDF2）并返回盐值
        /// </summary>
        /// <param name="password">密码</param>
        /// <param name="iterations">迭代次数</param>
        /// <returns>生成的密钥和盐值</returns>
        public (byte[] Key, byte[] Salt) DeriveKeyFromPassword(string password, int iterations = 10000)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("密码不能为空", nameof(password));

            var salt = StringUtil.GenerateRandomBytes(16); // 128位盐值
            var key = DeriveKeyFromPassword(password, salt, iterations);
            return (key, salt);
        }

        /// <summary>
        /// 验证密钥强度
        /// </summary>
        /// <param name="key">密钥</param>
        /// <returns>是否为弱密钥</returns>
        public bool IsWeakKey(byte[] key)
        {
            if (key == null || key.Length != DES_KEY_SIZE_BYTES)
                return false;

            // DES弱密钥检查
            var weakKeys = new byte[][]
            {
                new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
                new byte[] { 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
                new byte[] { 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E },
                new byte[] { 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 }
            };

            foreach (var weakKey in weakKeys)
            {
                if (StringUtil.ByteArraysEqual(key, weakKey))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// 验证加密参数
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        private void ValidateEncryptParameters(byte[] data, byte[] key, byte[]? iv)
        {
            if (data == null || data.Length == 0)
                throw new DataException("待加密数据不能为空");

            ValidateKey(key);
            ValidateIV(iv);
        }

        /// <summary>
        /// 验证解密参数
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        private void ValidateDecryptParameters(byte[] encryptedData, byte[] key, byte[]? iv)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                throw new DataException("待解密数据不能为空");

            ValidateKey(key);
            ValidateIV(iv);
        }

        /// <summary>
        /// 验证密钥
        /// </summary>
        /// <param name="key">密钥</param>
        private void ValidateKey(byte[] key)
        {
            if (key == null)
                throw new KeyException("密钥不能为null");

            if (key.Length == 0)
                throw new KeyException("密钥不能为空");

            if (key.Length != DES_KEY_SIZE_BYTES)
                throw new KeyException($"DES密钥长度必须为{DES_KEY_SIZE_BYTES}字节，当前长度为{key.Length}字节");

            // 检查是否为弱密钥
            if (IsWeakKey(key))
                throw new KeyException("检测到DES弱密钥，请使用其他密钥");
        }

        /// <summary>
        /// 检查是否为ECB模式
        /// </summary>
        private bool IsECBMode => _mode == CipherMode.ECB;

        /// <summary>
        /// 检查模式是否需要IV
        /// </summary>
        private bool RequiresIV => !IsECBMode;

        /// <summary>
        /// 验证IV
        /// </summary>
        /// <param name="iv">初始化向量</param>
        private void ValidateIV(byte[]? iv)
        {
            if (iv == null)
                return;

            if (iv.Length == 0)
                throw new KeyException("IV不能为空");

            // ECB模式不需要IV
            if (_mode == CipherMode.ECB)
                throw new KeyException("ECB模式不支持IV参数");

            // 其他模式需要8字节IV
            if (iv.Length != DES_IV_SIZE_BYTES)
                throw new KeyException($"IV长度必须为{DES_IV_SIZE_BYTES}字节，当前长度为{iv.Length}字节");
        }
    }
}
