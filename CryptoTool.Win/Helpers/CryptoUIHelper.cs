

using CryptoTool.Win.Enums;

namespace CryptoTool.Win.Helpers
{
    /// <summary>
    /// UI辅助的帮助类，统一枚举映射
    /// </summary>
    public static class CryptoUIHelper
    {

        /// <summary>
        /// 从UI字符串转换为UIOutputFormat
        /// </summary>
        public static UIOutputFormat ParseOutputFormat(string formatText)
        {
            return FormatConversionHelper.ParseOutputFormat(formatText);
        }

        /// <summary>
        /// 从UI字符串转换为UIInputFormat
        /// </summary>
        public static UIInputFormat ParseInputFormat(string formatText)
        {
            return FormatConversionHelper.ParseInputFormat(formatText);
        }


        /// <summary>
        /// 从UI字符串转换为RSAKeyType
        /// </summary>
        public static RSAKeyType ParseRSAKeyType(int index)
        {
            return index switch
            {
                0 => RSAKeyType.PKCS1,
                1 => RSAKeyType.PKCS8,
                _ => RSAKeyType.PKCS8
            };
        }

        /// <summary>
        /// 从UI字符串转换为KeyFormat
        /// </summary>
        public static KeyFormat ParseKeyFormat(int index)
        {
            return index switch
            {
                0 => KeyFormat.PEM,
                1 => KeyFormat.Base64,
                2 => KeyFormat.Hex,
                _ => KeyFormat.Base64
            };
        }

    }
}