

using CryptoTool.Win.Enums;

namespace CryptoTool.Win.Helpers
{
    /// <summary>
    /// UI�����İ����࣬ͳһö��ӳ��
    /// </summary>
    public static class CryptoUIHelper
    {

        /// <summary>
        /// ��UI�ַ���ת��ΪUIOutputFormat
        /// </summary>
        public static UIOutputFormat ParseOutputFormat(string formatText)
        {
            return FormatConversionHelper.ParseOutputFormat(formatText);
        }

        /// <summary>
        /// ��UI�ַ���ת��ΪUIInputFormat
        /// </summary>
        public static UIInputFormat ParseInputFormat(string formatText)
        {
            return FormatConversionHelper.ParseInputFormat(formatText);
        }


        /// <summary>
        /// ��UI�ַ���ת��ΪRSAKeyType
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
        /// ��UI�ַ���ת��ΪKeyFormat
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