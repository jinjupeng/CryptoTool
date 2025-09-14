using CryptoTool.Algorithm.Utils;
using CryptoTool.Win.Enums;
using System;
using System.Text;

namespace CryptoTool.Win.Helpers
{

    /// <summary>
    /// ��ʽת�������� - ר������UI������ݸ�ʽת��
    /// ����ʽת���߼���Common����ƶ���UI�㣬��ߴ���ְ�����
    /// </summary>
    public static class FormatConversionHelper
    {
        #region �����ʽת������

        /// <summary>
        /// ���ַ���ת��Ϊ�ֽ�����
        /// </summary>
        /// <param name="str">�����ַ���</param>
        /// <param name="format">�����ʽ</param>
        /// <param name="encoding">�ַ�����</param>
        /// <returns>�ֽ�����</returns>
        public static byte[] StringToBytes(string str, UIInputFormat format, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(str))
                throw new ArgumentException("�����ַ�������Ϊ��", nameof(str));

            encoding = encoding ?? Encoding.UTF8;

            return format switch
            {
                UIInputFormat.UTF8 => encoding.GetBytes(str),
                UIInputFormat.Base64 => Convert.FromBase64String(str),
                UIInputFormat.Hex => CryptoUtil.HexToBytes(str),
                _ => throw new ArgumentException($"��֧�ֵ������ʽ: {format}")
            };
        }

        /// <summary>
        /// ���ֽ�����ת��Ϊ�ַ���
        /// </summary>
        /// <param name="bytes">�ֽ�����</param>
        /// <param name="format">�����ʽ</param>
        /// <param name="encoding">�ַ�����</param>
        /// <returns>�ַ���</returns>
        public static string BytesToString(byte[] bytes, UIOutputFormat format, Encoding encoding = null)
        {
            if (bytes == null || bytes.Length == 0)
                throw new ArgumentException("�ֽ����鲻��Ϊ��", nameof(bytes));

            encoding = encoding ?? Encoding.UTF8;

            return format switch
            {
                UIOutputFormat.UTF8 => encoding.GetString(bytes),
                UIOutputFormat.Base64 => Convert.ToBase64String(bytes),
                UIOutputFormat.Hex => CryptoUtil.BytesToHex(bytes),
                UIOutputFormat.PEM => Convert.ToBase64String(bytes), // PEMʹ��Base64����
                _ => throw new ArgumentException($"��֧�ֵ������ʽ: {format}")
            };
        }

        #endregion

        #region ��ʽ��������

        /// <summary>
        /// ����UI�����ʽ�ַ���
        /// </summary>
        /// <param name="formatText">��ʽ�ı�</param>
        /// <returns>�����ʽö��</returns>
        public static UIInputFormat ParseInputFormat(string formatText)
        {
            return formatText?.ToUpperInvariant() switch
            {
                "BASE64" => UIInputFormat.Base64,
                "HEX" => UIInputFormat.Hex,
                "UTF8" => UIInputFormat.UTF8,
                "TEXT" => UIInputFormat.UTF8, // ���ݾɰ汾
                _ => UIInputFormat.UTF8 // Ĭ��ֵ
            };
        }

        /// <summary>
        /// ����UI�����ʽ�ַ���
        /// </summary>
        /// <param name="formatText">��ʽ�ı�</param>
        /// <returns>�����ʽö��</returns>
        public static UIOutputFormat ParseOutputFormat(string formatText)
        {
            return formatText?.ToUpperInvariant() switch
            {
                "BASE64" => UIOutputFormat.Base64,
                "HEX" => UIOutputFormat.Hex,
                "UTF8" => UIOutputFormat.UTF8,
                "TEXT" => UIOutputFormat.UTF8, // ���ݾɰ汾
                "PEM" => UIOutputFormat.PEM,
                _ => UIOutputFormat.Base64 // Ĭ��ֵ
            };
        }

        #endregion


        #region ��ʽת������

        /// <summary>
        /// ת���ַ�����ʽ
        /// </summary>
        /// <param name="input">�����ַ���</param>
        /// <param name="fromFormat">Դ��ʽ</param>
        /// <param name="toFormat">Ŀ���ʽ</param>
        /// <param name="encoding">�ַ�����</param>
        /// <returns>ת������ַ���</returns>
        public static string ConvertStringFormat(string input, UIInputFormat fromFormat, UIOutputFormat toFormat, Encoding encoding = null)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // ��ת��Ϊ�ֽ�����
            byte[] bytes = StringToBytes(input, fromFormat, encoding);
            
            // ��ת��ΪĿ���ʽ
            return BytesToString(bytes, toFormat, encoding);
        }

        #endregion
    }
}