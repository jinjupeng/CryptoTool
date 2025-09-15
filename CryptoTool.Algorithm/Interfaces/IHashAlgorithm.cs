using System.Threading.Tasks;

namespace CryptoTool.Algorithm.Interfaces
{

    /// <summary>
    /// 哈希算法接口
    /// </summary>
    public interface IHashAlgorithm : ICryptoAlgorithm
    {
        /// <summary>
        /// 计算哈希值
        /// </summary>
        /// <param name="data">待计算数据</param>
        /// <returns>哈希值</returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// 异步计算哈希值
        /// </summary>
        Task<byte[]> ComputeHashAsync(byte[] data);

        /// <summary>
        /// 获取哈希值长度（字节）
        /// </summary>
        int HashLength { get; }
    }
}
