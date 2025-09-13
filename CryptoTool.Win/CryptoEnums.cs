namespace CryptoTool.Win.Enums
{
    /// <summary>
    /// 通用加密模式枚举
    /// </summary>
    public enum CryptoMode
    {
        /// <summary>
        /// 电子密码本模式 (Electronic Codebook)
        /// </summary>
        ECB,
        /// <summary>
        /// 密码块链接模式 (Cipher Block Chaining)
        /// </summary>
        CBC,
        /// <summary>
        /// 密码反馈模式 (Cipher Feedback)
        /// </summary>
        CFB,
        /// <summary>
        /// 输出反馈模式 (Output Feedback)
        /// </summary>
        OFB,
        /// <summary>
        /// 计数器模式 (Counter Mode)
        /// </summary>
        CTR,
        /// <summary>
        /// 伽罗瓦/计数器模式 (Galois/Counter Mode)
        /// </summary>
        GCM
    }

    /// <summary>
    /// 通用填充模式枚举
    /// </summary>
    public enum CryptoPaddingMode
    {
        /// <summary>
        /// PKCS7填充（推荐）- 最常用的标准填充模式
        /// </summary>
        PKCS7,
        /// <summary>
        /// PKCS5填充 - 与PKCS7类似，但专门用于8字节块大小
        /// </summary>
        PKCS5,
        /// <summary>
        /// 零填充 - 使用零字节填充
        /// </summary>
        Zeros,
        /// <summary>
        /// ISO10126填充 - 使用随机字节填充，最后一字节表示填充长度
        /// </summary>
        ISO10126,
        /// <summary>
        /// ANSIX923填充 - 填充字节为零，最后一字节表示填充长度
        /// </summary>
        ANSIX923,
        /// <summary>
        /// 无填充 - 要求输入数据长度必须是块大小的整数倍
        /// </summary>
        None
    }

    /// <summary>
    /// 加密算法类型枚举
    /// </summary>
    public enum AlgorithmType
    {
        /// <summary>
        /// AES算法
        /// </summary>
        AES,
        /// <summary>
        /// DES算法
        /// </summary>
        DES,
        /// <summary>
        /// 3DES算法
        /// </summary>
        TripleDES,
        /// <summary>
        /// RSA算法
        /// </summary>
        RSA,
        /// <summary>
        /// SM2算法
        /// </summary>
        SM2,
        /// <summary>
        /// SM3算法
        /// </summary>
        SM3,
        /// <summary>
        /// SM4算法
        /// </summary>
        SM4,
        /// <summary>
        /// MD5算法
        /// </summary>
        MD5,
        /// <summary>
        /// SHA1算法
        /// </summary>
        SHA1,
        /// <summary>
        /// SHA256算法
        /// </summary>
        SHA256,
        /// <summary>
        /// SHA384算法
        /// </summary>
        SHA384,
        /// <summary>
        /// SHA512算法
        /// </summary>
        SHA512
    }

    /// <summary>
    /// 密钥长度枚举
    /// </summary>
    public enum KeySize
    {
        /// <summary>
        /// 64位密钥
        /// </summary>
        Key64 = 64,
        /// <summary>
        /// 128位密钥
        /// </summary>
        Key128 = 128,
        /// <summary>
        /// 192位密钥
        /// </summary>
        Key192 = 192,
        /// <summary>
        /// 256位密钥
        /// </summary>
        Key256 = 256,
        /// <summary>
        /// 512位密钥
        /// </summary>
        Key512 = 512,
        /// <summary>
        /// 1024位密钥
        /// </summary>
        Key1024 = 1024,
        /// <summary>
        /// 2048位密钥
        /// </summary>
        Key2048 = 2048,
        /// <summary>
        /// 4096位密钥
        /// </summary>
        Key4096 = 4096
    }

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
        SM3withSM2
    }

    /// <summary>
    /// 密钥格式枚举 - 统一RSA和其他算法的密钥格式定义
    /// </summary>
    public enum KeyFormat
    {
        /// <summary>
        /// PEM格式
        /// </summary>
        PEM,
        /// <summary>
        /// Base64格式
        /// </summary>
        Base64,
        /// <summary>
        /// 十六进制格式
        /// </summary>
        Hex,
        /// <summary>
        /// PKCS1格式
        /// </summary>
        PKCS1,
        /// <summary>
        /// PKCS8格式
        /// </summary>
        PKCS8
    }

    /// <summary>
    /// RSA密钥类型枚举
    /// </summary>
    public enum RSAKeyType
    {
        /// <summary>
        /// PKCS1格式
        /// </summary>
        PKCS1,
        /// <summary>
        /// PKCS8格式
        /// </summary>
        PKCS8
    }

    /// <summary>
    /// RSA填充方式枚举
    /// </summary>
    public enum RSAPadding
    {
        /// <summary>
        /// PKCS1填充
        /// </summary>
        PKCS1,
        /// <summary>
        /// OAEP填充
        /// </summary>
        OAEP,
        /// <summary>
        /// 无填充
        /// </summary>
        NoPadding
    }
}
