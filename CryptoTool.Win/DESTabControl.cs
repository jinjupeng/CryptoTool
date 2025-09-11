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
            comboDESKeyFormat.SelectedIndex = 0; // Base64
            comboDESIVFormat.SelectedIndex = 0; // Base64
            comboDESPlaintextFormat.SelectedIndex = 0; // Text
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

                string key = DESUtil.GenerateKey();
                textDESKey.Text = key;
                SetStatus("DES密钥生成完成");
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

                string iv = DESUtil.GenerateIV();
                textDESIV.Text = iv;
                SetStatus("DES初始向量生成完成");
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

                string plaintext = GetPlaintextFromFormat();
                string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                string cipherText = DESUtil.EncryptByDES(plaintext, textDESKey.Text, desMode, desPadding, outputFormat, iv);
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

                string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                string plainText = DESUtil.DecryptByDES(textDESCipherText.Text, textDESKey.Text, desMode, desPadding, inputFormat, iv);
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
            comboDESIVFormat.Enabled = needsIV;
            labelDESIVFormat.Enabled = needsIV;

            if (!needsIV)
            {
                textDESIV.Text = "";
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

                        string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                        DESUtil.EncryptFile(openDialog.FileName, saveDialog.FileName, textDESKey.Text, desMode, desPadding, iv);

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

                        string iv = string.IsNullOrEmpty(textDESIV.Text) ? null : textDESIV.Text;

                        DESUtil.DecryptFile(openDialog.FileName, saveDialog.FileName, textDESKey.Text, desMode, desPadding, iv);

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
            if (plaintextFormat == "Text")
                return plaintext;

            // 其他格式暂时直接返回，后续可以扩展格式转换功能
            return plaintext;
        }

        private void SetPlaintextFromFormat(string decryptedText)
        {
            string plaintextFormat = comboDESPlaintextFormat.SelectedItem.ToString();

            // 根据格式设置显示内容
            if (plaintextFormat == "Text")
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
