using CryptoTool.Common.Enums;
using System.Text;

namespace CryptoTool.Common.Interfaces
{

    /// <summary>
    /// 非对称加密提供者接口
    /// </summary>
    public interface IAsymmetricCryptoProvider
    {
        /// <summary>
        /// 生成密钥对 - 返回PEM格式
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥对（PEM格式）</returns>
        (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize = KeySize.Key2048);

        /// <summary>
        /// 生成密钥对 - 指定输出格式
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="format">密钥格式</param>
        /// <returns>密钥对（指定格式）</returns>
        (string PublicKey, string PrivateKey) GenerateKeyPair(KeySize keySize, KeyFormat format);

        /// <summary>
        /// 使用公钥加密 - 返回Base64格式
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <returns>密文（Base64格式）</returns>
        string EncryptWithPublicKey(string plaintext, string publicKey);

        /// <summary>
        /// 使用公钥加密 - 指定编码和填充方式
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>密文（Base64格式）</returns>
        string EncryptWithPublicKey(string plaintext, string publicKey, RSAPadding padding, Encoding encoding = null);

        /// <summary>
        /// 使用公钥加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <returns>密文字节数组</returns>
        byte[] EncryptWithPublicKey(byte[] data, string publicKey, RSAPadding padding = RSAPadding.PKCS1);

        /// <summary>
        /// 使用私钥解密 - 输入Base64格式
        /// </summary>
        /// <param name="ciphertext">密文（Base64格式）</param>
        /// <param name="privateKey">私钥</param>
        /// <returns>明文</returns>
        string DecryptWithPrivateKey(string ciphertext, string privateKey);

        /// <summary>
        /// 使用私钥解密 - 指定编码和填充方式
        /// </summary>
        /// <param name="ciphertext">密文（Base64格式）</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>明文</returns>
        string DecryptWithPrivateKey(string ciphertext, string privateKey, RSAPadding padding, Encoding encoding = null);

        /// <summary>
        /// 使用私钥解密字节数组
        /// </summary>
        /// <param name="data">密文字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="padding">填充方式（RSA专用）</param>
        /// <returns>明文字节数组</returns>
        byte[] DecryptWithPrivateKey(byte[] data, string privateKey, RSAPadding padding = RSAPadding.PKCS1);

        /// <summary>
        /// 签名 - 返回Base64格式
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>签名（Base64格式）</returns>
        string Sign(string data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA);

        /// <summary>
        /// 签名 - 指定编码方式
        /// </summary>
        /// <param name="data">待签名数据</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>签名（Base64格式）</returns>
        string Sign(string data, string privateKey, SignatureAlgorithm algorithm, Encoding encoding);

        /// <summary>
        /// 签名字节数组
        /// </summary>
        /// <param name="data">待签名数据字节数组</param>
        /// <param name="privateKey">私钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>签名字节数组</returns>
        byte[] Sign(byte[] data, string privateKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA);

        /// <summary>
        /// 验签 - 输入Base64格式签名
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名（Base64格式）</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>验签结果</returns>
        bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA);

        /// <summary>
        /// 验签 - 指定编码方式
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="signature">签名（Base64格式）</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <param name="encoding">字符编码</param>
        /// <returns>验签结果</returns>
        bool Verify(string data, string signature, string publicKey, SignatureAlgorithm algorithm, Encoding encoding);

        /// <summary>
        /// 验签字节数组
        /// </summary>
        /// <param name="data">原始数据字节数组</param>
        /// <param name="signature">签名字节数组</param>
        /// <param name="publicKey">公钥</param>
        /// <param name="algorithm">签名算法</param>
        /// <returns>验签结果</returns>
        bool Verify(byte[] data, byte[] signature, string publicKey, SignatureAlgorithm algorithm = SignatureAlgorithm.SHA256withRSA);
    }
}
