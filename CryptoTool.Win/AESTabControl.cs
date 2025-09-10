using CryptoTool.Common;
using System;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace CryptoTool.Win
{
    public partial class AESTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public AESTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboAESMode.SelectedIndex = 1; // CBC
            comboAESPadding.SelectedIndex = 0; // PKCS7
            comboAESKeyFormat.SelectedIndex = 0; // Base64
            comboAESIVFormat.SelectedIndex = 0; // Base64
            comboAESPlaintextFormat.SelectedIndex = 0; // Text
            comboAESCiphertextFormat.SelectedIndex = 0; // Base64
            comboAESKeySize.SelectedIndex = 2; // AES256
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region AES功能

        private void btnGenerateAESKey_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成AES密钥...");

                string keySizeText = comboAESKeySize.SelectedItem.ToString();
                AESUtil.AESKeySize keySize = (AESUtil.AESKeySize)Enum.Parse(typeof(AESUtil.AESKeySize), keySizeText);

                string key = AESUtil.GenerateKey(keySize);
                textAESKey.Text = key;
                SetStatus($"AES密钥生成完成 - {keySizeText}位");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成AES密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成AES密钥失败");
            }
        }

        private void btnGenerateAESIV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成AES初始向量...");

                string iv = AESUtil.GenerateIV();
                textAESIV.Text = iv;
                SetStatus("AES初始向量生成完成");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成AES初始向量失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成AES初始向量失败");
            }
        }

        private void btnAESEncrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textAESPlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textAESKey.Text))
                {
                    MessageBox.Show("请先生成或输入AES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboAESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                {
                    MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行AES加密...");

                string modeText = comboAESMode.SelectedItem.ToString();
                string paddingText = comboAESPadding.SelectedItem.ToString();
                string outputFormatText = comboAESCiphertextFormat.SelectedItem.ToString();

                AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);
                AESUtil.OutputFormat outputFormat = (AESUtil.OutputFormat)Enum.Parse(typeof(AESUtil.OutputFormat), outputFormatText);

                string plaintext = GetPlaintextFromFormat();
                string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                string cipherText = AESUtil.EncryptByAES(plaintext, textAESKey.Text, aesMode, aesPadding, outputFormat, iv);
                textAESCipherText.Text = cipherText;

                SetStatus($"AES加密完成 - 使用{modeText}模式，输出{outputFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"AES加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("AES加密失败");
            }
        }

        private void btnAESDecrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textAESCipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textAESKey.Text))
                {
                    MessageBox.Show("请先生成或输入AES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboAESMode.SelectedItem.ToString();
                if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                {
                    MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行AES解密...");

                string modeText = comboAESMode.SelectedItem.ToString();
                string paddingText = comboAESPadding.SelectedItem.ToString();
                string outputFormatText = comboAESCiphertextFormat.SelectedItem.ToString();

                AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);
                AESUtil.OutputFormat inputFormat = (AESUtil.OutputFormat)Enum.Parse(typeof(AESUtil.OutputFormat), outputFormatText);

                string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                string plainText = AESUtil.DecryptByAES(textAESCipherText.Text, textAESKey.Text, aesMode, aesPadding, inputFormat, iv);
                SetPlaintextFromFormat(plainText);

                SetStatus($"AES解密完成 - 使用{modeText}模式，输入{outputFormatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"AES解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("AES解密失败");
            }
        }

        private void comboAESMode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当选择ECB模式时，禁用初始向量相关控件
            bool needsIV = comboAESMode.SelectedItem.ToString() != "ECB";
            textAESIV.Enabled = needsIV;
            btnGenerateAESIV.Enabled = needsIV;
            comboAESIVFormat.Enabled = needsIV;
            labelAESIVFormat.Enabled = needsIV;

            if (!needsIV)
            {
                textAESIV.Text = "";
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

                        if (string.IsNullOrEmpty(textAESKey.Text))
                        {
                            MessageBox.Show("请先生成或输入AES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboAESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                        {
                            MessageBox.Show($"{mode}模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("正在加密文件...");

                        string modeText = comboAESMode.SelectedItem.ToString();
                        string paddingText = comboAESPadding.SelectedItem.ToString();

                        AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                        AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);

                        string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                        AESUtil.EncryptFile(openDialog.FileName, saveDialog.FileName, textAESKey.Text, aesMode, aesPadding, iv);

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

                        if (string.IsNullOrEmpty(textAESKey.Text))
                        {
                            MessageBox.Show("请先输入AES密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        string mode = comboAESMode.SelectedItem.ToString();
                        if (mode != "ECB" && string.IsNullOrEmpty(textAESIV.Text))
                        {
                            MessageBox.Show($"{mode}模式需要初始向量，请先输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            return;
                        }

                        SetStatus("正在解密文件...");

                        string modeText = comboAESMode.SelectedItem.ToString();
                        string paddingText = comboAESPadding.SelectedItem.ToString();

                        AESUtil.AESMode aesMode = (AESUtil.AESMode)Enum.Parse(typeof(AESUtil.AESMode), modeText);
                        AESUtil.AESPadding aesPadding = (AESUtil.AESPadding)Enum.Parse(typeof(AESUtil.AESPadding), paddingText);

                        string iv = string.IsNullOrEmpty(textAESIV.Text) ? null : textAESIV.Text;

                        AESUtil.DecryptFile(openDialog.FileName, saveDialog.FileName, textAESKey.Text, aesMode, aesPadding, iv);

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
            string plaintextFormat = comboAESPlaintextFormat.SelectedItem.ToString();
            string plaintext = textAESPlainText.Text;

            // 如果是Text格式，直接返回
            if (plaintextFormat == "Text")
                return plaintext;

            // 其他格式暂时直接返回，后续可以扩展格式转换功能
            return plaintext;
        }

        private void SetPlaintextFromFormat(string decryptedText)
        {
            string plaintextFormat = comboAESPlaintextFormat.SelectedItem.ToString();

            // 根据格式设置显示内容
            if (plaintextFormat == "Text")
            {
                textAESPlainText.Text = decryptedText;
            }
            else if (plaintextFormat == "Base64")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textAESPlainText.Text = Convert.ToBase64String(bytes);
                }
                catch
                {
                    textAESPlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else if (plaintextFormat == "Hex")
            {
                try
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(decryptedText);
                    textAESPlainText.Text = BitConverter.ToString(bytes).Replace("-", "");
                }
                catch
                {
                    textAESPlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else
            {
                textAESPlainText.Text = decryptedText;
            }
        }

        #endregion
    }
}