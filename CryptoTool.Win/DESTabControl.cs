using CryptoTool.Common;
using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CryptoTool.Win
{
    public partial class DESTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public DESTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboDESMode.SelectedIndex = 0; // CBC
            comboDESPadding.SelectedIndex = 0; // PKCS7
            comboDESKeyFormat.SelectedIndex = 0; // UTF8
            comboDESIVFormat.SelectedIndex = 0; // UTF8
            comboDESPlaintextFormat.SelectedIndex = 0; // UTF8
            comboDESCiphertextFormat.SelectedIndex = 0; // Base64
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region DES功能

        private void btnGenerateDESKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成DES密钥...");

                string keyFormat = comboDESKeyFormat.SelectedItem.ToString();
                DESUtil.InputFormat format = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), keyFormat);
                string key = DESUtil.GenerateKey(format);
                textDESKey.Text = key;
                SetStatus($"DES密钥生成完成 - {keyFormat}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成DES密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成DES密钥失败");
            }
        }

        private void btnGenerateDESIV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成DES初始向量...");

                string ivFormat = comboDESIVFormat.SelectedItem.ToString();
                DESUtil.InputFormat format = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), ivFormat);
                string iv = DESUtil.GenerateIV(format);
                textDESIV.Text = iv;
                SetStatus($"DES初始向量生成完成 - {ivFormat}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成DES初始向量失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成DES初始向量失败");
            }
        }

        private void btnDESEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textDESPlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textDESKey.Text))
                {
                    MessageBox.Show("请先生成或输入DES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboDESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textDESIV.Text))
                {
                    MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行DES加密...");

                string modeText = comboDESMode.SelectedItem.ToString();
                string paddingText = comboDESPadding.SelectedItem.ToString();
                string outputFormatText = comboDESCiphertextFormat.SelectedItem.ToString();
                DESUtil.DESMode desMode = (DESUtil.DESMode)Enum.Parse(typeof(DESUtil.DESMode), modeText);
                DESUtil.DESPadding desPadding = (DESUtil.DESPadding)Enum.Parse(typeof(DESUtil.DESPadding), paddingText);
                DESUtil.OutputFormat outputFormat = (DESUtil.OutputFormat)Enum.Parse(typeof(DESUtil.OutputFormat), outputFormatText);
                DESUtil.InputFormat keyFormat = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), comboDESKeyFormat.SelectedItem.ToString());

                string plaintext = GetPlaintextFromFormat();
                string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                string cipherText = DESUtil.EncryptByDES(plaintext, textDESKey.Text, keyFormat, desMode, desPadding, outputFormat, iv);
                textDESCipherText.Text = cipherText;

                SetStatus($"DES加密完成 - 使用{modeText}模式，输出{outputFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"DES加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("DES加密失败");
            }
        }

        private void btnDESDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textDESCipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textDESKey.Text))
                {
                    MessageBox.Show("请先生成或输入DES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboDESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textDESIV.Text))
                {
                    MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行DES解密...");

                string modeText = comboDESMode.SelectedItem.ToString();
                string paddingText = comboDESPadding.SelectedItem.ToString();
                string outputFormatText = comboDESCiphertextFormat.SelectedItem.ToString();
                DESUtil.DESMode desMode = (DESUtil.DESMode)Enum.Parse(typeof(DESUtil.DESMode), modeText);
                DESUtil.DESPadding desPadding = (DESUtil.DESPadding)Enum.Parse(typeof(DESUtil.DESPadding), paddingText);
                DESUtil.OutputFormat inputFormat = (DESUtil.OutputFormat)Enum.Parse(typeof(DESUtil.OutputFormat), outputFormatText);
                DESUtil.InputFormat keyFormat = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), comboDESKeyFormat.SelectedItem.ToString());

                string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                string plainText = DESUtil.DecryptByDES(textDESCipherText.Text, textDESKey.Text, keyFormat, desMode, desPadding, inputFormat, iv);
                SetPlaintextFromFormat(plainText);

                SetStatus($"DES解密完成 - 使用{modeText}模式，输入{outputFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"DES解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("DES解密失败");
            }
        }

        private void comboDESMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当选择ECB模式时，禁用初始向量相关控件
            bool needsIV = comboDESMode.SelectedItem.ToString() != "ECB";
            textDESIV.Enabled = needsIV;
            btnGenerateDESIV.Enabled = needsIV;
            btnConvertDESIV.Enabled = needsIV;
            comboDESIVFormat.Enabled = needsIV;
            labelDESIVFormat.Enabled = needsIV;

            if (!needsIV)
            {
                textDESIV.Text = "";
            }
        }

        private void btnConvertDESKey_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textDESKey.Text))
                {
                    MessageBox.Show("请先输入密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在转换密钥格式...");

                string currentFormat = comboDESKeyFormat.SelectedItem.ToString();
                string newFormat;
                if (currentFormat == "UTF8") newFormat = "Base64";
                else if (currentFormat == "Base64") newFormat = "Hex";
                else newFormat = "UTF8";

                string convertedKey = ConvertKeyFormat(textDESKey.Text, currentFormat, newFormat);
                textDESKey.Text = convertedKey;
                comboDESKeyFormat.SelectedItem = newFormat;

                SetStatus($"密钥格式转换完成 - 从{currentFormat}转换为{newFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"密钥格式转换失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("密钥格式转换失败");
            }
        }

        private void btnConvertDESIV_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textDESIV.Text))
                {
                    MessageBox.Show("请先输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在转换IV格式...");

                string currentFormat = comboDESIVFormat.SelectedItem.ToString();
                string newFormat;
                if (currentFormat == "UTF8") newFormat = "Base64";
                else if (currentFormat == "Base64") newFormat = "Hex";
                else newFormat = "UTF8";

                string convertedIV = ConvertIVFormat(textDESIV.Text, currentFormat, newFormat);
                textDESIV.Text = convertedIV;
                comboDESIVFormat.SelectedItem = newFormat;

                SetStatus($"IV格式转换完成 - 从{currentFormat}转换为{newFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"IV格式转换失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("IV格式转换失败");
            }
        }

        #endregion

        #region 文件操作

        private void btnEncryptFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openDialog = new OpenFileDialog())
                {
                    openDialog.Title = "选择要加密的文件";
                    openDialog.Filter = "所有文件|*.*";
                    
                    if (openDialog.ShowDialog() != DialogResult.OK)
                        return;

                    using (SaveFileDialog saveDialog = new SaveFileDialog())
                    {
                        saveDialog.Title = "保存加密文件";
                        saveDialog.Filter = "加密文件|*.enc|所有文件|*.*";
                        saveDialog.FileName = Path.GetFileNameWithoutExtension(openDialog.FileName) + ".enc";
                        
                        if (saveDialog.ShowDialog() != DialogResult.OK)
                            return;

                        if (string.IsNullOrEmpty(textDESKey.Text))
                        {
                            MessageBox.Show("请先生成或输入DES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboDESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textDESIV.Text))
                        {
                            MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("正在加密文件...");

                        string modeText = comboDESMode.SelectedItem.ToString();
                        string paddingText = comboDESPadding.SelectedItem.ToString();
                        DESUtil.DESMode desMode = (DESUtil.DESMode)Enum.Parse(typeof(DESUtil.DESMode), modeText);
                        DESUtil.DESPadding desPadding = (DESUtil.DESPadding)Enum.Parse(typeof(DESUtil.DESPadding), paddingText);
                        DESUtil.InputFormat keyFormat = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), comboDESKeyFormat.SelectedItem.ToString());

                        string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                        DESUtil.EncryptFile(openDialog.FileName, saveDialog.FileName, textDESKey.Text, keyFormat, desMode, desPadding, iv);

                        SetStatus($"文件加密完成：{saveDialog.FileName}");
                        MessageBox.Show("文件加密完成！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"文件加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("文件加密失败");
            }
        }

        private void btnDecryptFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openDialog = new OpenFileDialog())
                {
                    openDialog.Title = "选择要解密的文件";
                    openDialog.Filter = "加密文件|*.enc|所有文件|*.*";
                    
                    if (openDialog.ShowDialog() != DialogResult.OK)
                        return;

                    using (SaveFileDialog saveDialog = new SaveFileDialog())
                    {
                        saveDialog.Title = "保存解密文件";
                        saveDialog.Filter = "所有文件|*.*";
                        string originalName = Path.GetFileNameWithoutExtension(openDialog.FileName);
                        if (originalName.EndsWith(".enc"))
                            originalName = originalName.Substring(0, originalName.Length - 4);
                        saveDialog.FileName = originalName;
                        
                        if (saveDialog.ShowDialog() != DialogResult.OK)
                            return;

                        if (string.IsNullOrEmpty(textDESKey.Text))
                        {
                            MessageBox.Show("请先输入DES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboDESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textDESIV.Text))
                        {
                            MessageBox.Show($"{mode}模式需要初始向量，请先输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("正在解密文件...");

                        string modeText = comboDESMode.SelectedItem.ToString();
                        string paddingText = comboDESPadding.SelectedItem.ToString();
                        DESUtil.DESMode desMode = (DESUtil.DESMode)Enum.Parse(typeof(DESUtil.DESMode), modeText);
                        DESUtil.DESPadding desPadding = (DESUtil.DESPadding)Enum.Parse(typeof(DESUtil.DESPadding), paddingText);
                        DESUtil.InputFormat keyFormat = (DESUtil.InputFormat)Enum.Parse(typeof(DESUtil.InputFormat), comboDESKeyFormat.SelectedItem.ToString());

                        string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                        DESUtil.DecryptFile(openDialog.FileName, saveDialog.FileName, textDESKey.Text, keyFormat, desMode, desPadding, iv);

                        SetStatus($"文件解密完成：{saveDialog.FileName}");
                        MessageBox.Show("文件解密完成！", "成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"文件解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("文件解密失败");
            }
        }

        #endregion

        #region 辅助方法

        private string GetPlaintextFromFormat()
        {
            string plaintextFormat = comboDESPlaintextFormat.SelectedItem.ToString();
            string plaintext = textDESPlainText.Text;

            // 如果是Text格式，直接返回
            if (plaintextFormat == "UTF8")
                return plaintext;

            // 其他格式暂时直接返回，后续可以扩展格式转换功能
            return plaintext;
        }

        /// <summary>
        /// 转换密钥格式
        /// </summary>
        /// <param name="key">原始密钥</param>
        /// <param name="fromFormat">源格式</param>
        /// <param name="toFormat">目标格式</param>
        /// <returns>转换后的密钥</returns>
        private string ConvertKeyFormat(string key, string fromFormat, string toFormat)
        {
            if (string.IsNullOrEmpty(key) || fromFormat == toFormat)
                return key;

            try
            {
                // 先解码为字节数组
                byte[] keyBytes = GetKeyBytesFromFormat(key, fromFormat);
                
                // 再编码为目标格式
                return EncodeKeyBytes(keyBytes, toFormat);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"密钥格式转换失败：{ex.Message}", ex);
            }
        }

        /// <summary>
        /// 转换IV格式
        /// </summary>
        /// <param name="iv">原始IV</param>
        /// <param name="fromFormat">源格式</param>
        /// <param name="toFormat">目标格式</param>
        /// <returns>转换后的IV</returns>
        private string ConvertIVFormat(string iv, string fromFormat, string toFormat)
        {
            if (string.IsNullOrEmpty(iv) || fromFormat == toFormat)
                return iv;

            try
            {
                // 先解码为字节数组
                byte[] ivBytes = GetIVBytesFromFormat(iv, fromFormat);
                
                // 再编码为目标格式
                return EncodeIVBytes(ivBytes, toFormat);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"IV格式转换失败：{ex.Message}", ex);
            }
        }

        /// <summary>
        /// 从指定格式获取密钥字节数组
        /// </summary>
        private byte[] GetKeyBytesFromFormat(string key, string format)
        {
            switch (format)
            {
                case "Base64":
                    return Convert.FromBase64String(key);
                case "Hex":
                    return ConvertFromHexString(key);
                case "UTF8":
                default:
                    return Encoding.UTF8.GetBytes(key);
            }
        }

        /// <summary>
        /// 从指定格式获取IV字节数组
        /// </summary>
        private byte[] GetIVBytesFromFormat(string iv, string format)
        {
            switch (format)
            {
                case "Base64":
                    return Convert.FromBase64String(iv);
                case "Hex":
                    return ConvertFromHexString(iv);
                case "UTF8":
                default:
                    return Encoding.UTF8.GetBytes(iv);
            }
        }

        /// <summary>
        /// 将密钥字节数组编码为指定格式
        /// </summary>
        private string EncodeKeyBytes(byte[] keyBytes, string format)
        {
            switch (format)
            {
                case "Base64":
                    return Convert.ToBase64String(keyBytes);
                case "Hex":
                    return ConvertToHexString(keyBytes);
                case "UTF8":
                default:
                    return Encoding.UTF8.GetString(keyBytes);
            }
        }

        /// <summary>
        /// 将IV字节数组编码为指定格式
        /// </summary>
        private string EncodeIVBytes(byte[] ivBytes, string format)
        {
            switch (format)
            {
                case "Base64":
                    return Convert.ToBase64String(ivBytes);
                case "Hex":
                    return ConvertToHexString(ivBytes);
                case "UTF8":
                default:
                    return Encoding.UTF8.GetString(ivBytes);
            }
        }

        /// <summary>
        /// 将字节数组转换为16进制字符串
        /// </summary>
        private string ConvertToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        /// <summary>
        /// 将16进制字符串转换为字节数组
        /// </summary>
        private byte[] ConvertFromHexString(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("16进制字符串不能为空", nameof(hexString));

            if (hexString.Length % 2 != 0)
                throw new ArgumentException("16进制字符串长度必须为偶数", nameof(hexString));

            byte[] result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return result;
        }

        private void SetPlaintextFromFormat(string decryptedText)
        {
            string plaintextFormat = comboDESPlaintextFormat.SelectedItem.ToString();

            // 根据格式设置显示内容
            if (plaintextFormat == "UTF8")
            {
                textDESPlainText.Text = decryptedText;
            }
            else if (plaintextFormat == "Base64")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textDESPlainText.Text = Convert.ToBase64String(bytes);
                }
                catch
                {
                    textDESPlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else if (plaintextFormat == "Hex")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textDESPlainText.Text = BitConverter.ToString(bytes).Replace("-", "");
                }
                catch
                {
                    textDESPlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else
            {
                textDESPlainText.Text = decryptedText;
            }
        }

        #endregion
    }
}
