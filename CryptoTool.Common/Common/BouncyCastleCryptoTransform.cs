using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;

namespace CryptoTool.Common.Common
{
    /// <summary>
    /// BouncyCastle加密转换器适配器
    /// </summary>
    public class BouncyCastleCryptoTransform : ICryptoTransform
    {
        private readonly IBufferedCipher _cipher;

        public BouncyCastleCryptoTransform(IBufferedCipher cipher)
        {
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => _cipher.GetBlockSize();

        public int OutputBlockSize => _cipher.GetBlockSize();

        public void Dispose()
        {
            // BouncyCastle的IBufferedCipher没有实现IDisposable
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return _cipher.ProcessBytes(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return _cipher.DoFinal(inputBuffer, inputOffset, inputCount);
        }
    }
}
