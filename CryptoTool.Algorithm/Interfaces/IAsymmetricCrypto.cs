using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoTool.Algorithm.Interfaces
{
    /// <summary>
    /// 非对称加密算法接口
    /// </summary>
    public interface IAsymmetricCrypto : ICryptoAlgorithm
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>加密后的数据</returns>
        byte[] Encrypt(byte[] data, byte[] publicKey);

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>解密后的数据</returns>
        byte[] Decrypt(byte[] encryptedData, byte[] privateKey);

        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <returns>密钥对</returns>
        (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair();

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>签名数据</returns>
        byte[] Sign(byte[] data, byte[] privateKey);

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>验证结果</returns>
        bool VerifySign(byte[] data, byte[] signature, byte[] publicKey);
    }
}
