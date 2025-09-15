namespace CryptoTool.Algorithm.Enums
{
    /// <summary>
    /// 对称加密模式枚举
    /// </summary>
    public enum SymmetricCipherMode
    {
        /// <summary>
        /// （推荐）密码块链接模式 (Cipher Block Chaining)
        /// </summary>
        CBC,
        /// <summary>
        /// 电子密码本模式 (Electronic Codebook)
        /// </summary>
        ECB,
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
        CTR
    }
}
