using System;
using System.IO;
using System.Threading.Tasks;
using CryptoTool.Common.Enums;

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
        /// 加密字符串
        /// </summary>
        /// <param name="plaintext">明文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="outputFormat">输出格式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>密文</returns>
        string Encrypt(string plaintext, string key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, OutputFormat outputFormat = OutputFormat.Base64, string iv = null);

        /// <summary>
        /// 解密字符串
        /// </summary>
        /// <param name="ciphertext">密文</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="inputFormat">输入格式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>明文</returns>
        string Decrypt(string ciphertext, string key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, InputFormat inputFormat = InputFormat.Base64, string iv = null);

        /// <summary>
        /// 加密字节数组
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的字节数组</returns>
        byte[] Encrypt(byte[] data, byte[] key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, byte[] iv = null);

        /// <summary>
        /// 解密字节数组
        /// </summary>
        /// <param name="data">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="mode">加密模式</param>
        /// <param name="padding">填充模式</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的字节数组</returns>
        byte[] Decrypt(byte[] data, byte[] key, CipherMode mode = CipherMode.CBC, 
            PaddingMode padding = PaddingMode.PKCS7, byte[] iv = null);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null);

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
            CipherMode mode = CipherMode.CBC, PaddingMode padding = PaddingMode.PKCS7, string iv = null);

        /// <summary>
        /// 生成密钥
        /// </summary>
        /// <param name="keySize">密钥长度</param>
        /// <param name="format">输出格式</param>
        /// <returns>密钥字符串</returns>
        string GenerateKey(KeySize keySize = KeySize.Key256, OutputFormat format = OutputFormat.Base64);

        /// <summary>
        /// 生成初始化向量
        /// </summary>
        /// <param name="format">输出格式</param>
        /// <returns>初始化向量字符串</returns>
        string GenerateIV(OutputFormat format = OutputFormat.Base64);

        /// <summary>
        /// 验证密钥有效性
        /// </summary>
        /// <param name="key">密钥</param>
        /// <param name="format">密钥格式</param>
        /// <returns>是否有效</returns>
        bool ValidateKey(string key, InputFormat format = InputFormat.UTF8);
    }

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

    /// <summary>
    /// 哈希提供者接口
    /// </summary>
    public interface IHashProvider
    {
        /// <summary>
        /// 算法类型
        /// </summary>
        AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 计算哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        string ComputeHash(string data, OutputFormat outputFormat = OutputFormat.Hex);

        /// <summary>
        /// 计算字节数组哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        string ComputeHash(byte[] data, OutputFormat outputFormat = OutputFormat.Hex);

        /// <summary>
        /// 计算文件哈希值
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        string ComputeFileHash(string filePath, OutputFormat outputFormat = OutputFormat.Hex);

        /// <summary>
        /// 计算流哈希值
        /// </summary>
        /// <param name="stream">流</param>
        /// <param name="outputFormat">输出格式</param>
        /// <returns>哈希值</returns>
        string ComputeStreamHash(Stream stream, OutputFormat outputFormat = OutputFormat.Hex);

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        bool VerifyHash(string data, string expectedHash, InputFormat inputFormat = InputFormat.Hex);

        /// <summary>
        /// 验证字节数组哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值</param>
        /// <param name="inputFormat">输入格式</param>
        /// <returns>是否匹配</returns>
        bool VerifyHash(byte[] data, string expectedHash, InputFormat inputFormat = InputFormat.Hex);
    }
}
