using CryptoTool.Common.Enums;
using System.Threading.Tasks;

namespace CryptoTool.Common.Interfaces
{
    /// <summary>
    /// 通用加密提供者接口
    /// </summary>
    public interface ICryptoProvider
    {
        /// <summary>
        /// 算法类型
        /// </summary>
        AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 加密字符串 - 基础版本，只处理核心加密逻辑
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>密文字节数组的Base64编码</returns>
        string Encrypt(string plaintext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 解密字符串 - 基础版本，只处理核心解密逻辑
        /// </summary>
        /// <param name="ciphertext">密文（Base64编码）</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>明文</returns>
        string Decrypt(string ciphertext, string key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的字节数组</returns>
        byte[] Encrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null);

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的字节数组</returns>
        byte[] Decrypt(byte[] data, byte[] key, CryptoMode mode = CryptoMode.CBC,
            CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, byte[] iv = null);

        /// <summary>
        /// 加密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        void EncryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 解密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        void DecryptFile(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 异步加密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>异步任务</returns>
        Task EncryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 异步解密文件
        /// </summary>
        /// <param name="inputFilePath">输入文件路径</param>
        /// <param name="outputFilePath">输出文件路径</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>异步任务</returns>
        Task DecryptFileAsync(string inputFilePath, string outputFilePath, string key,
            CryptoMode mode = CryptoMode.CBC, CryptoPaddingMode padding = CryptoPaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 生成密钥 - 返回Base64格式
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <returns>密钥字符串（Base64格式）</returns>
        string GenerateKey(KeySize keySize = KeySize.Key256);

        /// <summary>
        /// 生成初始化向量 - 返回Base64格式
        /// </summary>
        /// <returns>初始化向量字符串（Base64格式）</returns>
        string GenerateIV();

        /// <summary>
        /// 验证密钥有效性
        /// </summary>
        /// <param name="key">密钥</param>
        /// <returns>是否有效</returns>
        bool ValidateKey(string key);
    }
}
