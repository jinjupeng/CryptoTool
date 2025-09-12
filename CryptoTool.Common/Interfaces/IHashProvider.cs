using CryptoTool.Common.Enums;
using System.IO;

namespace CryptoTool.Common.Interfaces
{

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
        /// 计算哈希值 - 返回十六进制格式
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值（十六进制格式）</returns>
        string ComputeHash(string data);

        /// <summary>
        /// 计算字节数组哈希值 - 返回十六进制格式
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值（十六进制格式）</returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// 计算文件哈希值 - 返回十六进制格式
        /// </summary>
        /// <param name="filePath">文件路径</param>
        /// <returns>哈希值（十六进制格式）</returns>
        string ComputeFileHash(string filePath);

        /// <summary>
        /// 计算流哈希值 - 返回十六进制格式
        /// </summary>
        /// <param name="stream">流</param>
        /// <returns>哈希值（十六进制格式）</returns>
        string ComputeStreamHash(Stream stream);

        /// <summary>
        /// 验证哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值（十六进制格式）</param>
        /// <returns>是否匹配</returns>
        bool VerifyHash(string data, string expectedHash);

        /// <summary>
        /// 验证字节数组哈希值
        /// </summary>
        /// <param name="data">原始数据</param>
        /// <param name="expectedHash">期望的哈希值（十六进制格式）</param>
        /// <returns>是否匹配</returns>
        bool VerifyHash(byte[] data, string expectedHash);
    }
}
