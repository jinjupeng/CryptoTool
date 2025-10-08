

namespace CryptoTool.Algorithm.Interfaces
{

    /// <summary>
    /// 对称加密算法接口
    /// </summary>
    public interface ISymmetricCrypto : ICryptoAlgorithm
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="data">待加密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>加密后的数据</returns>
        byte[] Encrypt(byte[] data, byte[] key, byte[]? iv = null);

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptedData">待解密数据</param>
        /// <param name="key">密钥</param>
        /// <param name="iv">初始化向量</param>
        /// <returns>解密后的数据</returns>
        byte[] Decrypt(byte[] encryptedData, byte[] key, byte[]? iv = null);

        /// <summary>
        /// 生成随机密钥
        /// </summary>
        /// <returns>随机密钥</returns>
        byte[] GenerateKey();

        /// <summary>
        /// 生成随机IV
        /// </summary>
        /// <returns>随机IV</returns>
        byte[] GenerateIV();
    }
}
