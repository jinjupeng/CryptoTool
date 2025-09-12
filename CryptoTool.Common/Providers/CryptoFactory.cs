using System;
using System.Collections.Generic;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Interfaces;
using CryptoTool.Common.Providers;
using CryptoTool.Common.Providers.GM;

namespace CryptoTool.Common.Providers
{
    /// <summary>
    /// 加密工具工厂类
    /// </summary>
    public static class CryptoFactory
    {
        /// <summary>
        /// 创建加密提供者
        /// </summary>
        /// <param name="algorithmType">算法类型</param>
        /// <returns>加密提供者</returns>
        public static ICryptoProvider CreateCryptoProvider(AlgorithmType algorithmType)
        {
            return algorithmType switch
            {
                AlgorithmType.AES => new AESProvider(),
                AlgorithmType.DES => new DESProvider(),
                AlgorithmType.SM4 => new SM4Provider(),
                _ => throw new NotSupportedException($"不支持的算法类型: {algorithmType}")
            };
        }

        /// <summary>
        /// 创建哈希提供者
        /// </summary>
        /// <param name="algorithmType">算法类型</param>
        /// <returns>哈希提供者</returns>
        public static IHashProvider CreateHashProvider(AlgorithmType algorithmType)
        {
            return algorithmType switch
            {
                AlgorithmType.SM3 => new SM3Provider(),
                AlgorithmType.MD5 => new MD5Provider(),
                _ => throw new NotSupportedException($"不支持的哈希算法类型: {algorithmType}")
            };
        }

        /// <summary>
        /// 获取所有支持的对称加密算法
        /// </summary>
        /// <returns>算法类型列表</returns>
        public static List<AlgorithmType> GetSupportedSymmetricAlgorithms()
        {
            return new List<AlgorithmType>
            {
                AlgorithmType.AES,
                AlgorithmType.DES,
                AlgorithmType.SM4
            };
        }

        /// <summary>
        /// 获取所有支持的哈希算法
        /// </summary>
        /// <returns>算法类型列表</returns>
        public static List<AlgorithmType> GetSupportedHashAlgorithms()
        {
            return new List<AlgorithmType>
            {
                AlgorithmType.SM3,
                AlgorithmType.MD5,
                AlgorithmType.SHA1,
                AlgorithmType.SHA256,
                AlgorithmType.SHA384,
                AlgorithmType.SHA512
            };
        }
    }
}