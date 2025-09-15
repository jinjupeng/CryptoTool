using CryptoTool.Algorithm.Enums;
using System;
using System.Security.Cryptography;

namespace CryptoTool.Algorithm.Utils
{
    /// <summary>
    /// 加密填充模式辅助类
    /// </summary>
    public static class CryptoPaddingUtil
    {
        /// <summary>
        /// 将AsymmetricPaddingMode转换为RSAEncryptionPadding
        /// </summary>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>RSA加密填充</returns>
        public static RSAEncryptionPadding GetRSAEncryptionPadding(AsymmetricPaddingMode paddingMode)
        {
            return paddingMode switch
            {
                AsymmetricPaddingMode.PKCS1 => RSAEncryptionPadding.Pkcs1,
                AsymmetricPaddingMode.OAEP => RSAEncryptionPadding.OaepSHA1,
                AsymmetricPaddingMode.PSS => throw new NotSupportedException("PSS填充不支持加密操作"),
                AsymmetricPaddingMode.None => throw new NotSupportedException("RSA不支持无填充加密"),
                _ => throw new ArgumentException($"不支持的填充模式: {paddingMode}")
            };
        }

        /// <summary>
        /// 将AsymmetricPaddingMode转换为RSASignaturePadding
        /// </summary>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>RSA签名填充</returns>
        public static RSASignaturePadding GetRSASignaturePadding(AsymmetricPaddingMode paddingMode)
        {
            return paddingMode switch
            {
                AsymmetricPaddingMode.PKCS1 => RSASignaturePadding.Pkcs1,
                AsymmetricPaddingMode.PSS => RSASignaturePadding.Pss,
                AsymmetricPaddingMode.OAEP => throw new NotSupportedException("OAEP填充不支持签名操作"),
                AsymmetricPaddingMode.None => throw new NotSupportedException("RSA不支持无填充签名"),
                _ => throw new ArgumentException($"不支持的填充模式: {paddingMode}")
            };
        }

        /// <summary>
        /// 将SignatureAlgorithm转换为HashAlgorithmName和RSASignaturePadding
        /// </summary>
        /// <param name="signatureAlgorithm">签名算法</param>
        /// <returns>哈希算法名称和RSA签名填充</returns>
        public static (HashAlgorithmName HashAlgorithm, RSASignaturePadding SignaturePadding) GetRSAAlgorithm(SignatureAlgorithm signatureAlgorithm)
        {
            return signatureAlgorithm switch
            {
                SignatureAlgorithm.MD5withRSA => (HashAlgorithmName.MD5, RSASignaturePadding.Pkcs1),
                SignatureAlgorithm.SHA1withRSA => (HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
                SignatureAlgorithm.SHA256withRSA => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                SignatureAlgorithm.SHA384withRSA => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
                SignatureAlgorithm.SHA512withRSA => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
                SignatureAlgorithm.SHA1withRSA_PSS => (HashAlgorithmName.SHA1, RSASignaturePadding.Pss),
                SignatureAlgorithm.SHA256withRSA_PSS => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
                SignatureAlgorithm.SHA384withRSA_PSS => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss),
                SignatureAlgorithm.SHA512withRSA_PSS => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss),
                _ => throw new ArgumentException($"RSA不支持的签名算法: {signatureAlgorithm}")
            };
        }

        /// <summary>
        /// 检查签名算法是否适用于RSA
        /// </summary>
        /// <param name="signatureAlgorithm">签名算法</param>
        /// <returns>是否适用于RSA</returns>
        public static bool IsRSACompatible(SignatureAlgorithm signatureAlgorithm)
        {
            return signatureAlgorithm switch
            {
                SignatureAlgorithm.MD5withRSA => true,
                SignatureAlgorithm.SHA1withRSA => true,
                SignatureAlgorithm.SHA256withRSA => true,
                SignatureAlgorithm.SHA384withRSA => true,
                SignatureAlgorithm.SHA512withRSA => true,
                SignatureAlgorithm.SHA1withRSA_PSS => true,
                SignatureAlgorithm.SHA256withRSA_PSS => true,
                SignatureAlgorithm.SHA384withRSA_PSS => true,
                SignatureAlgorithm.SHA512withRSA_PSS => true,
                _ => false
            };
        }

        /// <summary>
        /// 检查签名算法是否适用于SM2
        /// </summary>
        /// <param name="signatureAlgorithm">签名算法</param>
        /// <returns>是否适用于SM2</returns>
        public static bool IsSM2Compatible(SignatureAlgorithm signatureAlgorithm)
        {
            return signatureAlgorithm == SignatureAlgorithm.SM3withSM2;
        }

        /// <summary>
        /// 获取填充模式的描述
        /// </summary>
        /// <param name="paddingMode">填充模式</param>
        /// <returns>描述文本</returns>
        public static string GetPaddingDescription(AsymmetricPaddingMode paddingMode)
        {
            return paddingMode switch
            {
                AsymmetricPaddingMode.PKCS1 => "PKCS#1 v1.5填充 - 传统RSA填充模式",
                AsymmetricPaddingMode.OAEP => "OAEP填充 - 更安全的RSA填充模式",
                AsymmetricPaddingMode.PSS => "PSS填充 - 用于RSA签名的安全填充模式",
                AsymmetricPaddingMode.None => "无填充 - 要求数据长度必须是密钥长度的整数倍",
                _ => "未知填充模式"
            };
        }

        /// <summary>
        /// 获取签名算法的描述
        /// </summary>
        /// <param name="signatureAlgorithm">签名算法</param>
        /// <returns>描述文本</returns>
        public static string GetSignatureDescription(SignatureAlgorithm signatureAlgorithm)
        {
            return signatureAlgorithm switch
            {
                SignatureAlgorithm.MD5withRSA => "MD5withRSA - 使用MD5哈希的RSA签名（不推荐，安全性较低）",
                SignatureAlgorithm.SHA1withRSA => "SHA1withRSA - 使用SHA1哈希的RSA签名（不推荐，安全性较低）",
                SignatureAlgorithm.SHA256withRSA => "SHA256withRSA - 使用SHA256哈希的RSA签名（推荐）",
                SignatureAlgorithm.SHA384withRSA => "SHA384withRSA - 使用SHA384哈希的RSA签名（推荐）",
                SignatureAlgorithm.SHA512withRSA => "SHA512withRSA - 使用SHA512哈希的RSA签名（推荐）",
                SignatureAlgorithm.SHA1withRSA_PSS => "SHA1withRSA-PSS - 使用SHA1哈希和PSS填充的RSA签名",
                SignatureAlgorithm.SHA256withRSA_PSS => "SHA256withRSA-PSS - 使用SHA256哈希和PSS填充的RSA签名（推荐）",
                SignatureAlgorithm.SHA384withRSA_PSS => "SHA384withRSA-PSS - 使用SHA384哈希和PSS填充的RSA签名（推荐）",
                SignatureAlgorithm.SHA512withRSA_PSS => "SHA512withRSA-PSS - 使用SHA512哈希和PSS填充的RSA签名（推荐）",
                SignatureAlgorithm.SM3withSM2 => "SM3withSM2 - 使用SM3哈希的SM2签名（国密标准）",
                SignatureAlgorithm.ECDSAwithSHA1 => "ECDSAwithSHA1 - 使用SHA1哈希的ECDSA签名",
                SignatureAlgorithm.ECDSAwithSHA256 => "ECDSAwithSHA256 - 使用SHA256哈希的ECDSA签名",
                SignatureAlgorithm.ECDSAwithSHA384 => "ECDSAwithSHA384 - 使用SHA384哈希的ECDSA签名",
                SignatureAlgorithm.ECDSAwithSHA512 => "ECDSAwithSHA512 - 使用SHA512哈希的ECDSA签名",
                SignatureAlgorithm.EdDSA => "EdDSA - 使用Ed25519曲线的EdDSA签名",
                SignatureAlgorithm.DSAwithSHA1 => "DSAwithSHA1 - 使用SHA1哈希的DSA签名",
                SignatureAlgorithm.DSAwithSHA256 => "DSAwithSHA256 - 使用SHA256哈希的DSA签名",
                _ => "未知签名算法"
            };
        }
    }
}
