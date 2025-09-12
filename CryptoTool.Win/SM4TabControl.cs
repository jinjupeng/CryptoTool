using CryptoTool.Common.Providers.GM;
using CryptoTool.Common.Enums;
using CryptoTool.Win.Helpers;

namespace CryptoTool.Win
{
    public partial class SM4TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM4TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            comboSM4Mode.SelectedIndex = 0; // ECB
            comboSM4Padding.SelectedIndex = 0; // PKCS7
            comboSM4KeyFormat.SelectedIndex = 0; // Base64
            comboSM4IVFormat.SelectedIndex = 0; // Base64
            comboSM4PlaintextFormat.SelectedIndex = 0; // Text
            comboSM4CiphertextFormat.SelectedIndex = 0; // Base64
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        public void UpdateKeyFromMedicare(string key)
        {
            textSM4Key.Text = key;
            comboSM4KeyFormat.SelectedItem = "Hex";
        }

        #region SM4功能

        private void btnGenerateSM4Key_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4密钥...");

                string formatText = comboSM4KeyFormat.SelectedItem?.ToString() ?? "";
                OutputFormat format = CryptoUIHelper.ParseOutputFormat(formatText);

                var provider = new SM4Provider();
                string key = provider.GenerateKey(KeySize.Key128, format);
                textSM4Key.Text = key;
                SetStatus($"SM4密钥生成完成 - {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4密钥失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4密钥失败");
            }
        }

        private void btnGenerateSM4IV_Click(object sender, EventArgs e)
        {
            try
            {
                SetStatus("正在生成SM4初始向量...");

                string formatText = comboSM4IVFormat.SelectedItem?.ToString() ?? "";
                OutputFormat format = CryptoUIHelper.ParseOutputFormat(formatText);

                var provider = new SM4Provider();
                string iv = provider.GenerateIV(format);
                textSM4IV.Text = iv;
                SetStatus($"SM4初始向量生成完成 - {formatText}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"生成SM4初始向量失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("生成SM4初始向量失败");
            }
        }

        private void btnSM4Encrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4PlainText.Text))
                {
                    MessageBox.Show("请输入明文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem?.ToString() ?? "";
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4加密...");

                // 使用CryptoUIHelper解析枚举
                CryptoMode cryptoMode = CryptoUIHelper.ParseCryptoMode(mode);
                CryptoPaddingMode paddingMode = CryptoUIHelper.ParsePaddingMode(comboSM4Padding.SelectedItem?.ToString() ?? "");
                OutputFormat outputFormat = CryptoUIHelper.ParseOutputFormat(comboSM4CiphertextFormat.SelectedItem?.ToString() ?? "");

                string plaintext = GetPlaintextFromFormat();
                string? iv = string.IsNullOrEmpty(textSM4IV.Text) ? null : textSM4IV.Text;

                var provider = new SM4Provider();
                string cipherText = provider.Encrypt(plaintext, textSM4Key.Text, cryptoMode, paddingMode, outputFormat, iv);
                textSM4CipherText.Text = cipherText;

                SetStatus($"SM4加密完成 - 使用{mode}模式，输出{comboSM4CiphertextFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4加密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4加密失败");
            }
        }

        private void btnSM4Decrypt_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM4CipherText.Text))
                {
                    MessageBox.Show("请输入密文！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM4Key.Text))
                {
                    MessageBox.Show("请先生成或输入SM4密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string mode = comboSM4Mode.SelectedItem?.ToString() ?? "";
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4解密...");

                // 使用CryptoUIHelper解析枚举
                CryptoMode cryptoMode = CryptoUIHelper.ParseCryptoMode(mode);
                CryptoPaddingMode paddingMode = CryptoUIHelper.ParsePaddingMode(comboSM4Padding.SelectedItem?.ToString() ?? "");
                InputFormat inputFormat = CryptoUIHelper.ParseInputFormat(comboSM4CiphertextFormat.SelectedItem?.ToString() ?? "");

                string? iv = string.IsNullOrEmpty(textSM4IV.Text) ? null : textSM4IV.Text;

                var provider = new SM4Provider();
                string plainText = provider.Decrypt(textSM4CipherText.Text, textSM4Key.Text, cryptoMode, paddingMode, inputFormat, iv);
                SetPlaintextFromFormat(plainText);

                SetStatus($"SM4解密完成 - 使用{mode}模式，输入{comboSM4CiphertextFormat.SelectedItem}格式");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM4解密失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM4解密失败");
            }
        }

        private void comboSM4Mode_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当选择ECB模式时，禁用初始向量相关控件
            bool isCBC = comboSM4Mode.SelectedItem?.ToString() == "CBC";
            textSM4IV.Enabled = isCBC;
            btnGenerateSM4IV.Enabled = isCBC;
            comboSM4IVFormat.Enabled = isCBC;

            if (!isCBC)
            {
                textSM4IV.Text = "";
            }
        }

        private void comboSM4IVFormat_SelectedIndexChanged(object sender, EventArgs e)
        {
            // 当格式变化时，如果当前有IV内容，尝试转换格式
            if (string.IsNullOrEmpty(textSM4IV.Text)) return;

            try
            {
                // 暂不实现自动格式转换，避免错误转换
                // 用户需要重新生成IV或手动输入正确格式的IV
            }
            catch
            {
                // 格式转换失败，忽略
            }
        }

        #endregion

        #region 辅助方法

        private string GetPlaintextFromFormat()
        {
            string? plaintextFormat = comboSM4PlaintextFormat.SelectedItem?.ToString();
            string plaintext = textSM4PlainText.Text;

            // 如果是Text格式，直接返回
            if (plaintextFormat == "Text")
                return plaintext;

            // 其他格式暂时直接返回，后续可以扩展格式转换功能
            return plaintext;
        }

        private void SetPlaintextFromFormat(string decryptedText)
        {
            string? plaintextFormat = comboSM4PlaintextFormat.SelectedItem?.ToString();

            // 根据格式设置显示内容
            if (plaintextFormat == "Text")
            {
                textSM4PlainText.Text = decryptedText;
            }
            else if (plaintextFormat == "Base64")
            {
                try
                {
                    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(decryptedText);
                    textSM4PlainText.Text = Convert.ToBase64String(bytes);
                }
                catch
                {
                    textSM4PlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else if (plaintextFormat == "Hex")
            {
                try
                {
                    byte[] bytes = System.Text.Encoding.UTF8.GetBytes(decryptedText);
                    textSM4PlainText.Text = BitConverter.ToString(bytes).Replace("-", "");
                }
                catch
                {
                    textSM4PlainText.Text = decryptedText; // 如果转换失败，直接显示
                }
            }
            else
            {
                textSM4PlainText.Text = decryptedText;
            }
        }

        #endregion
    }
}