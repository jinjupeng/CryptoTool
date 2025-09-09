using CryptoTool.Common.GM;
using System.Text;

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

                string formatText = comboSM4KeyFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string key = SM4Util.GenerateKey(format);
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

                string formatText = comboSM4IVFormat.SelectedItem.ToString();
                SM4Util.FormatType format = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), formatText);

                string iv = SM4Util.GenerateIV(format);
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

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4加密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string cipherText;
                if (mode == "ECB")
                {
                    cipherText = SM4Util.EncryptEcbWithFormat(textSM4PlainText.Text, textSM4Key.Text, keyFormat, plaintextFormat, ciphertextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    cipherText = SM4Util.EncryptCbcWithFormat(textSM4PlainText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, plaintextFormat, ciphertextFormat, padding);
                }

                textSM4CipherText.Text = cipherText;
                SetStatus($"SM4加密完成 - 使用{mode}模式，明文{plaintextFormatText}格式，输出{ciphertextFormatText}格式");
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

                string mode = comboSM4Mode.SelectedItem.ToString();
                if (mode == "CBC" && string.IsNullOrEmpty(textSM4IV.Text))
                {
                    MessageBox.Show("CBC模式需要初始向量，请先生成或输入初始向量！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在进行SM4解密...");

                string paddingText = comboSM4Padding.SelectedItem.ToString();
                string keyFormatText = comboSM4KeyFormat.SelectedItem.ToString();
                string plaintextFormatText = comboSM4PlaintextFormat.SelectedItem.ToString();
                string ciphertextFormatText = comboSM4CiphertextFormat.SelectedItem.ToString();

                SM4Util.PaddingMode padding = (SM4Util.PaddingMode)Enum.Parse(typeof(SM4Util.PaddingMode), paddingText);
                SM4Util.FormatType keyFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), keyFormatText);
                SM4Util.FormatType plaintextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), plaintextFormatText);
                SM4Util.FormatType ciphertextFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ciphertextFormatText);

                string plainText;
                if (mode == "ECB")
                {
                    plainText = SM4Util.DecryptEcbWithFormat(textSM4CipherText.Text, textSM4Key.Text, keyFormat, ciphertextFormat, plaintextFormat, padding);
                }
                else // CBC
                {
                    string ivFormatText = comboSM4IVFormat.SelectedItem.ToString();
                    SM4Util.FormatType ivFormat = (SM4Util.FormatType)Enum.Parse(typeof(SM4Util.FormatType), ivFormatText);
                    plainText = SM4Util.DecryptCbcWithFormat(textSM4CipherText.Text, textSM4Key.Text, textSM4IV.Text, keyFormat, ivFormat, ciphertextFormat, plaintextFormat, padding);
                }

                textSM4PlainText.Text = plainText;
                SetStatus($"SM4解密完成 - 使用{mode}模式，密文{ciphertextFormatText}格式，输出{plaintextFormatText}格式");
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
            bool isCBC = comboSM4Mode.SelectedItem.ToString() == "CBC";
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
    }
}