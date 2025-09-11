using System.Text;
using CryptoTool.Common.Enums;

namespace CryptoTool.Common.Interfaces
{
    /// <summary>
    /// 非对称加密算法提供者接口
    /// </summary>
    public interface IAsymmetricCryptoProvider
    {
        /// <summary>
        /// 算法类型
        /// </summary>
        AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 加密字符串
        /// </summary>
        /// <param name="plainText">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文</returns>
        string Encrypt(string plainText, string publicKey, OutputFormat outputFormat = OutputFormat.Base64, Encoding encoding = null);

        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="cipherText">密文</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        string Decrypt(string cipherText, string privateKey, InputFormat inputFormat = InputFormat.Base64, Encoding encoding = null);

        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文</returns>
        byte[] Encrypt(byte[] data, string publicKey);

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文</returns>
        byte[] Decrypt(byte[] data, string privateKey);

        /// <summary>
        /// 签名
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名</returns>
        string Sign(string data, string privateKey, OutputFormat outputFormat = OutputFormat.Base64, Encoding encoding = null);

        /// <summary>
        /// 验证签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验证结果</returns>
        bool Verify(string data, string signature, string publicKey, InputFormat inputFormat = InputFormat.Base64, Encoding encoding = null);

        /// <summary>
        /// 生成密钥对
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>密钥对（公钥，私钥）</returns>
        (string publicKey, string privateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048, OutputFormat outputFormat = OutputFormat.PEM);
    }
}
