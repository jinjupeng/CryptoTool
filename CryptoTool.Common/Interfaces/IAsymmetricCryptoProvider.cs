using CryptoTool.Common.Enums;

namespace CryptoTool.Common.Interfaces
{

    /// <summary>
    /// 非对称加密提供者接口
    /// </summary>
    public interface IAsymmetricCryptoProvider : ICryptoProvider
    {
        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对</returns>
        (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048);

        /// <summary>
        /// 使用公钥加密
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密文</returns>
        string EncryptWithPublicKey(string plaintext, string publicKey, OutputFormat outputFormat = OutputFormat.Base64);

        /// <summary>
        /// 使用私钥解密
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>明文</returns>
        string DecryptWithPrivateKey(string ciphertext, string privateKey, InputFormat inputFormat = InputFormat.Base64);

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>签名</returns>
        string Sign(string data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA,
            OutputFormat outputFormat = OutputFormat.Base64);

        /// <summary>
        /// 验签
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>验签结果</returns>
        bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA,
            InputFormat inputFormat = InputFormat.Base64);
    }
}
