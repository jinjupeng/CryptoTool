using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoTool.Algorithm.Enums
{
    /// <summary>
    /// 签名算法枚举
    /// </summary>
    public enum SignatureAlgorithm
    {
        /// <summary>
        /// MD5withRSA
        /// </summary>
        MD5withRSA,
        /// <summary>
        /// SHA1withRSA (又称RSA1)
        /// </summary>
        SHA1withRSA,
        /// <summary>
        /// SHA256withRSA (又称RSA2)
        /// </summary>
        SHA256withRSA,
        /// <summary>
        /// SHA384withRSA
        /// </summary>
        SHA384withRSA,
        /// <summary>
        /// SHA512withRSA
        /// </summary>
        SHA512withRSA,
        /// <summary>
        /// SM3withSM2
        /// </summary>
        SM3withSM2,
        /// <summary>
        /// PSS填充的SHA1withRSA
        /// </summary>
        SHA1withRSA_PSS,
        /// <summary>
        /// PSS填充的SHA256withRSA
        /// </summary>
        SHA256withRSA_PSS,
        /// <summary>
        /// PSS填充的SHA384withRSA
        /// </summary>
        SHA384withRSA_PSS,
        /// <summary>
        /// PSS填充的SHA512withRSA
        /// </summary>
        SHA512withRSA_PSS,
        /// <summary>
        /// ECDSA with SHA1
        /// </summary>
        ECDSAwithSHA1,
        /// <summary>
        /// ECDSA with SHA256
        /// </summary>
        ECDSAwithSHA256,
        /// <summary>
        /// ECDSA with SHA384
        /// </summary>
        ECDSAwithSHA384,
        /// <summary>
        /// ECDSA with SHA512
        /// </summary>
        ECDSAwithSHA512,
        /// <summary>
        /// EdDSA (Ed25519)
        /// </summary>
        EdDSA,
        /// <summary>
        /// DSA with SHA1
        /// </summary>
        DSAwithSHA1,
        /// <summary>
        /// DSA with SHA256
        /// </summary>
        DSAwithSHA256
    }
}
