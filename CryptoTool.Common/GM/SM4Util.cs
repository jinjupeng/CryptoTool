using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Common;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoTool.Common.GM
{
    /// <summary>
    /// 使用BouncyCastle实现的SM4国密算法工具类
    /// </summary>
    public class SM4Util : BaseCryptoProvider
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
        protected override ICryptoTransform CreateCryptoTransform(byte[] key, byte[] iv, CipherMode mode, 
            PaddingMode padding, bool isEncryption)
        {
            // SM4使用BouncyCastle，需要特殊处理
            var engine = new SM4Engine();
            IBlockCipherPadding paddingProvider = GetPadding(padding);
            IBufferedCipher cipher;

            switch (mode)
            {
                case CipherMode.ECB:
                    cipher = new PaddedBufferedBlockCipher(engine, paddingProvider);
                    break;
                case CipherMode.CBC:
                    cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), paddingProvider);
                    break;
                case CipherMode.CFB:
                    cipher = new BufferedBlockCipher(new CfbBlockCipher(engine, BlockSize));
                    break;
                case CipherMode.OFB:
                    cipher = new BufferedBlockCipher(new OfbBlockCipher(engine, BlockSize));
                    break;
                default:
                    throw new NotSupportedException($"不支持的加密模式: {mode}");
            }

            ICipherParameters parameters;
            if (mode == CipherMode.ECB)
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
        protected override System.Security.Cryptography.CipherMode ConvertCipherMode(CipherMode mode)
        {
            // SM4使用BouncyCastle，不需要转换
            throw new NotSupportedException("SM4使用BouncyCastle实现，不需要转换CipherMode");
        }

        /// <summary>
        /// 转换填充模式
        /// </summary>
        protected override System.Security.Cryptography.PaddingMode ConvertPaddingMode(PaddingMode padding)
        {
            // SM4使用BouncyCastle，不需要转换
            throw new NotSupportedException("SM4使用BouncyCastle实现，不需要转换PaddingMode");
        }

        /// <summary>
        /// 获取BouncyCastle填充
        /// </summary>
        private static IBlockCipherPadding GetPadding(PaddingMode padding)
        {
            return padding switch
            {
                PaddingMode.PKCS7 => new Pkcs7Padding(),
                PaddingMode.PKCS5 => new Pkcs7Padding(), // PKCS5等同于PKCS7
                PaddingMode.Zeros => new ZeroBytePadding(),
                PaddingMode.None => null,
                _ => new Pkcs7Padding()
            };
        }

        #endregion
    }
}