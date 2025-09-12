using CryptoTool.Common.Common;
using CryptoTool.Common.Enums;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace CryptoTool.Common.Providers.GM
{
    /// <summary>
    /// 使用BouncyCastle实现的SM4国密算法工具类
    /// </summary>
    public class SM4Provider : BaseCryptoProvider
    {
        #region 属性

        /// <summary>
        /// 算法类型
        /// </summary>
        public override AlgorithmType AlgorithmType => AlgorithmType.SM4;

        /// <summary>
        /// 密钥长度（字节）
        /// </summary>
        protected override int KeySize => 16; // 128位

        /// <summary>
        /// 块大小（字节）
        /// </summary>
        protected override int BlockSize => 16; // 128位

        /// <summary>
        /// IV长度（字节）
        /// </summary>
        protected override int IVSize => 16; // 128位

        #endregion

        #region 抽象方法实现

        /// <summary>
        /// 创建加密器
        /// </summary>
        protected override ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CryptoMode mode,
            CryptoPaddingMode padding, bool isEncryption)
        {
            // SM4使用BouncyCastle，需要特殊处理
            var engine = new SM4Engine();
            IBlockCipherPadding paddingProvider = GetPadding(padding);
            IBufferedCipher cipher;

            switch (mode)
            {
                case CryptoMode.ECB:
                    cipher = new PaddedBufferedBlockCipher(engine, paddingProvider);
                    break;
                case CryptoMode.CBC:
                    cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), paddingProvider);
                    break;
                case CryptoMode.CFB:
                    cipher = new BufferedBlockCipher(new CfbBlockCipher(engine, BlockSize));
                    break;
                case CryptoMode.OFB:
                    cipher = new BufferedBlockCipher(new OfbBlockCipher(engine, BlockSize));
                    break;
                default:
                    throw new NotSupportedException($"不支持的加密模式: {mode}");
            }

            ICipherParameters parameters;
            if (mode == CryptoMode.ECB)
            {
                parameters = new KeyParameter(key);
            }
            else
            {
                parameters = new ParametersWithIV(new KeyParameter(key), iv);
            }

            cipher.Init(isEncryption, parameters);
            return new BouncyCastleCryptoTransform(cipher);
        }

        /// <summary>
        /// 转换加密模式
        /// </summary>
        protected override CipherMode ConvertCipherMode(CryptoMode mode)
        {
            // SM4使用BouncyCastle，不需要转换
            throw new NotSupportedException("SM4使用BouncyCastle实现，不需要转换CipherMode");
        }

        /// <summary>
        /// 转换填充模式
        /// </summary>
        protected override PaddingMode ConvertPaddingMode(CryptoPaddingMode padding)
        {
            // SM4使用BouncyCastle，不需要转换
            throw new NotSupportedException("SM4使用BouncyCastle实现，不需要转换PaddingMode");
        }

        /// <summary>
        /// 获取BouncyCastle填充
        /// </summary>
        private IBlockCipherPadding GetPadding(CryptoPaddingMode padding)
        {
            return padding switch
            {
                CryptoPaddingMode.PKCS7 => new Pkcs7Padding(),
                CryptoPaddingMode.PKCS5 => new Pkcs7Padding(), // PKCS5等同于PKCS7
                CryptoPaddingMode.Zeros => new ZeroBytePadding(),
                CryptoPaddingMode.None => null,
                _ => new Pkcs7Padding()
            };
        }

        #endregion

        #region 静态工具方法

        /// <summary>
        /// ECB模式加密字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥（16字节）</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptEcb(string plaintext, string key)
        {
            var sm4 = new SM4Provider();
            return sm4.Encrypt(plaintext, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7);
        }

        /// <summary>
        /// ECB模式解密字符串
        /// </summary>
        /// <param name="ciphertext">Base64编码的密文</param>
        /// <param name="key">密钥（16字节）</param>
        /// <returns>明文</returns>
        public static string DecryptEcb(string ciphertext, string key)
        {
            var sm4 = new SM4Provider();
            return sm4.Decrypt(ciphertext, key, CryptoMode.ECB, CryptoPaddingMode.PKCS7);
        }

        /// <summary>
        /// CBC模式加密字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥（16字节）</param>
        /// <param name="iv">初始化向量（16字节）</param>
        /// <returns>Base64编码的密文</returns>
        public static string EncryptCbc(string plaintext, string key, string iv)
        {
            var sm4 = new SM4Provider();
            return sm4.Encrypt(plaintext, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);
        }

        /// <summary>
        /// CBC模式解密字符串
        /// </summary>
        /// <param name="ciphertext">Base64编码的密文</param>
        /// <param name="key">密钥（16字节）</param>
        /// <param name="iv">初始化向量（16字节）</param>
        /// <returns>明文</returns>
        public static string DecryptCbc(string ciphertext, string key, string iv)
        {
            var sm4 = new SM4Provider();
            return sm4.Decrypt(ciphertext, key, CryptoMode.CBC, CryptoPaddingMode.PKCS7, iv);
        }

        #endregion
    }

    /// <summary>
    /// BouncyCastle到.NET CryptoTransform的适配器
    /// </summary>
    internal class BouncyCastleCryptoTransform : ICryptoTransform
    {
        private readonly IBufferedCipher _cipher;

        public BouncyCastleCryptoTransform(IBufferedCipher cipher)
        {
            _cipher = cipher;
        }

        public bool CanReuseTransform => false;
        public bool CanTransformMultipleBlocks => true;
        public int InputBlockSize => _cipher.GetBlockSize();
        public int OutputBlockSize => _cipher.GetBlockSize();

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            byte[] output = _cipher.ProcessBytes(inputBuffer, inputOffset, inputCount);
            Array.Copy(output, 0, outputBuffer, outputOffset, output.Length);
            return output.Length;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] partialOutput = _cipher.ProcessBytes(inputBuffer, inputOffset, inputCount);
            byte[] finalOutput = _cipher.DoFinal();
            
            byte[] result = new byte[partialOutput.Length + finalOutput.Length];
            Array.Copy(partialOutput, 0, result, 0, partialOutput.Length);
            Array.Copy(finalOutput, 0, result, partialOutput.Length, finalOutput.Length);
            
            return result;
        }

        public void Dispose()
        {
            // BouncyCastle cipher不需要显式释放
        }
    }
}