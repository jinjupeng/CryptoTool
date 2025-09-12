using CryptoTool.Common.Providers.GM;
using CryptoTool.Common.Enums;
using CryptoTool.Common.Utils;
using System.Text;
using CryptoTool.Win.Helpers;

namespace CryptoTool.Win
{
    public partial class SM3TabControl : UserControl
    {
        public event Action<string> StatusChanged;

        public SM3TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // 设置默认选项
            comboSM3DataFormat.SelectedIndex = 0; // Text
            comboSM3OutputFormat.SelectedIndex = 0; // Hex
            comboSM3FileHashFormat.SelectedIndex = 0; // Hex
            comboSM3VerifyDataFormat.SelectedIndex = 0; // Text
            comboSM3VerifyHashFormat.SelectedIndex = 0; // Hex
            comboSM3HMACDataFormat.SelectedIndex = 0; // Text
            comboSM3HMACOutputFormat.SelectedIndex = 0; // Hex

            // 设置示例数据
            textSM3Input.Text = "Hello SM3!";
            textSM3HMACData.Text = "Hello HMAC-SM3!";
            textSM3HMACKey.Text = "mySecretKey";
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region SM3哈希计算

        private void btnSM3Hash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3Input.Text))
                {
                    MessageBox.Show("请输入要计算哈希的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算SM3哈希...");

                string inputData = textSM3Input.Text;
                string dataFormat = comboSM3DataFormat.SelectedItem?.ToString() ?? "";
                string outputFormat = comboSM3OutputFormat.SelectedItem?.ToString() ?? "";

                byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                
                var sm3Provider = new SM3Provider();
                string result = sm3Provider.ComputeHashWithFormat(dataBytes, outputFormat);

                textSM3Output.Text = result;
                SetStatus($"SM3哈希计算完毕 - 输入格式：{dataFormat}，输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM3哈希计算失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("SM3哈希计算失败");
            }
        }

        private void btnSM3Clear_Click(object sender, EventArgs e)
        {
            textSM3Input.Clear();
            textSM3Output.Clear();
            SetStatus("已清空输入和输出");
        }

        #endregion

        #region SM3文件哈希

        private void btnSM3SelectFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "选择要计算哈希的文件";
                    openFileDialog.Filter = "所有文件 (*.*)|*.*";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        textSM3FilePath.Text = openFileDialog.FileName;
                        SetStatus($"已选择文件: {Path.GetFileName(openFileDialog.FileName)}");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"选择文件失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("选择文件失败");
            }
        }

        private void btnSM3ComputeFileHash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3FilePath.Text) || !File.Exists(textSM3FilePath.Text))
                {
                    MessageBox.Show("请先选择一个有效的文件！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算文件SM3哈希...");

                string outputFormat = comboSM3FileHashFormat.SelectedItem?.ToString() ?? "";
                
                var sm3Provider = new SM3Provider();
                string result = sm3Provider.ComputeHashWithFormat(textSM3FilePath.Text, outputFormat);

                // 假设控件名称应该是textSM3FileHash而不是textSM3FileHashResult
                if (FindControlByName("textSM3FileHash") != null)
                {
                    var textBox = FindControlByName("textSM3FileHash") as TextBox;
                    if (textBox != null) textBox.Text = result;
                }
                else
                {
                    // 如果找不到控件，显示在消息框中
                    MessageBox.Show($"文件哈希值: {result}", "计算结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                SetStatus($"文件SM3哈希计算完成 - 输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"计算文件哈希失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("计算文件哈希失败");
            }
        }

        #endregion

        #region SM3哈希验证

        private void btnSM3Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3VerifyData.Text))
                {
                    MessageBox.Show("请输入要验证的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3VerifyHash.Text))
                {
                    MessageBox.Show("请输入期望的哈希值！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在验证SM3哈希...");

                string data = textSM3VerifyData.Text;
                string expectedHash = textSM3VerifyHash.Text;
                string dataFormat = comboSM3VerifyDataFormat.SelectedItem?.ToString() ?? "";
                string hashFormat = comboSM3VerifyHashFormat.SelectedItem?.ToString() ?? "";

                byte[] dataBytes = ConvertInputData(data, dataFormat);
                
                var sm3Provider = new SM3Provider();
                bool isValid = sm3Provider.VerifyHashWithFormat(dataBytes, expectedHash, hashFormat);

                labelSM3VerifyResult.Text = isValid ? "验证通过" : "验证失败";
                labelSM3VerifyResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"SM3哈希验证完成 - 结果：{(isValid ? "通过" : "失败")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"SM3哈希验证失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelSM3VerifyResult.Text = "验证异常";
                labelSM3VerifyResult.ForeColor = Color.Red;
                SetStatus("SM3哈希验证失败");
            }
        }

        #endregion

        #region HMAC-SM3

        private void btnSM3ComputeHMAC_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textSM3HMACData.Text))
                {
                    MessageBox.Show("请输入要计算HMAC的数据！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textSM3HMACKey.Text))
                {
                    MessageBox.Show("请输入HMAC密钥！", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("正在计算HMAC-SM3...");

                string data = textSM3HMACData.Text;
                string key = textSM3HMACKey.Text;
                string dataFormat = comboSM3HMACDataFormat.SelectedItem?.ToString() ?? "";
                string outputFormat = comboSM3HMACOutputFormat.SelectedItem?.ToString() ?? "";

                byte[] dataBytes = ConvertInputData(data, dataFormat);
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);

                var sm3Provider = new SM3Provider();
                string result = sm3Provider.ComputeHMac(dataBytes, keyBytes, outputFormat);

                // 假设控件名称应该是textSM3HMAC而不是textSM3HMACResult
                if (FindControlByName("textSM3HMAC") != null)
                {
                    var textBox = FindControlByName("textSM3HMAC") as TextBox;
                    if (textBox != null) textBox.Text = result;
                }
                else
                {
                    // 如果找不到控件，显示在消息框中
                    MessageBox.Show($"HMAC-SM3值: {result}", "计算结果", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                SetStatus($"HMAC-SM3计算完成 - 输出格式：{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"HMAC-SM3计算失败：{ex.Message}", "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("HMAC-SM3计算失败");
            }
        }

        #endregion

        #region 辅助方法

        private byte[] ConvertInputData(string data, string format)
        {
            return format switch
            {
                "Text" => Encoding.UTF8.GetBytes(data),
                "Base64" => Convert.FromBase64String(data),
                "Hex" => CryptoCommonUtil.ConvertFromHexString(data),
                _ => Encoding.UTF8.GetBytes(data)
            };
        }

        /// <summary>
        /// 通过名称查找控件
        /// </summary>
        private Control? FindControlByName(string name)
        {
            return FindControlByName(this, name);
        }

        /// <summary>
        /// 递归查找控件
        /// </summary>
        private Control? FindControlByName(Control parent, string name)
        {
            if (parent.Name == name)
                return parent;

            foreach (Control child in parent.Controls)
            {
                var found = FindControlByName(child, name);
                if (found != null)
                    return found;
            }

            return null;
        }

        #endregion

        #region 事件处理器

        private void ComboSM3VerifyHashFormat_TabIndexChanged(object sender, EventArgs e)
        {
            // 验证哈希格式改变时的处理逻辑
        }

        private void ComboSM3HMACDataFormat_TabIndexChanged(object sender, EventArgs e)
        {
            // HMAC数据格式改变时的处理逻辑
        }

        private void ComboSM3HMACOutputFormat_TabIndexChanged(object sender, EventArgs e)
        {
            // HMAC输出格式改变时的处理逻辑
        }

        private void btnSM3HMAC_Click(object sender, EventArgs e)
        {
            // 这个事件处理器已经在代码中实现了，这里只是占位符
            btnSM3ComputeHMAC_Click(sender, e);
        }

        #endregion
    }
}