namespace CryptoTool.Algorithm.Interfaces
{
    /// <summary>
    /// 加密算法接口
    /// </summary>
    public interface ICryptoAlgorithm
    {
        /// <summary>
        /// 算法名称
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// 算法类型
        /// </summary>
        CryptoAlgorithmType AlgorithmType { get; }
    }


    /// <summary>
    /// 加密算法类型枚举
    /// </summary>
    public enum CryptoAlgorithmType
    {
        /// <summary>
        /// 对称加密
        /// </summary>
        Symmetric,
        /// <summary>
        /// 非对称加密
        /// </summary>
        Asymmetric,
        /// <summary>
        /// 哈希算法
        /// </summary>
        Hash
    }
}
