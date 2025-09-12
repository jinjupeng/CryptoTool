using CryptoTool.Common.Enums;
using CryptoTool.Common.Providers;
using CryptoTool.Common.Providers.GM;
using CryptoTool.Win.Helpers;

namespace CryptoTool.Win.Helpers
{
    /// <summary>
    /// UI�����İ����࣬ͳһö��ӳ��
    /// </summary>
    public static class CryptoUIHelper
    {
        /// <summary>
        /// ��UI�ַ���ת��ΪCryptoMode
        /// </summary>
        public static CryptoMode ParseCryptoMode(string modeText)
        {
            return modeText switch
            {
                "ECB" => CryptoMode.ECB,
                "CBC" => CryptoMode.CBC,
                "CFB" => CryptoMode.CFB,
                "OFB" => CryptoMode.OFB,
                _ => CryptoMode.CBC
            };
        }

        /// <summary>
        /// ��UI�ַ���ת��ΪCryptoPaddingMode
        /// </summary>
        public static CryptoPaddingMode ParsePaddingMode(string paddingText)
        {
            return paddingText switch
            {
                "PKCS7" => CryptoPaddingMode.PKCS7,
                "PKCS5" => CryptoPaddingMode.PKCS5,
                "Zeros" => CryptoPaddingMode.Zeros,
                "None" => CryptoPaddingMode.None,
                _ => CryptoPaddingMode.PKCS7
            };
        }

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
        /// ��UI�ַ���ת��ΪKeySize
        /// </summary>
        public static KeySize ParseKeySize(string keySizeText)
        {
            return keySizeText switch
            {
                "AES128" => KeySize.Key128,
                "AES192" => KeySize.Key192,
                "AES256" => KeySize.Key256,
                "DES" => KeySize.Key64,
                _ => KeySize.Key256
            };
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

        /// <summary>
        /// ��UI�ַ���ת��ΪRSAPadding
        /// </summary>
        public static RSAPadding ParseRSAPadding(string paddingText)
        {
            return paddingText switch
            {
                "PKCS1" => RSAPadding.PKCS1,
                "OAEP" => RSAPadding.OAEP,
                "NoPadding" => RSAPadding.NoPadding,
                _ => RSAPadding.PKCS1
            };
        }

        /// <summary>
        /// ��UI�ַ���ת��ΪSignatureAlgorithm
        /// </summary>
        public static SignatureAlgorithm ParseSignatureAlgorithm(int index)
        {
            return index switch
            {
                0 => SignatureAlgorithm.SHA1withRSA,
                1 => SignatureAlgorithm.SHA256withRSA,
                2 => SignatureAlgorithm.SHA384withRSA,
                3 => SignatureAlgorithm.SHA512withRSA,
                _ => SignatureAlgorithm.SHA256withRSA
            };
        }
    }
}