using System.IO;
using CryptoTool.Common.Enums;

namespace CryptoTool.Common.Interfaces
{
    /// <summary>
    /// 哈希算法提供者接口
    /// </summary>
    public interface IHashProvider
    {
        /// <summary>
        /// 算法类型
        /// </summary>
        AlgorithmType AlgorithmType { get; }

        /// <summary>
        /// 计算字符串哈希值
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
        /// 验证字符串哈希值
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
