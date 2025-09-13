using CryptoTool.Algorithm.Algorithms.MD5;
using CryptoTool.Algorithm.Enums;
using CryptoTool.Algorithm.Utils;
using System.Text;

namespace CryptoTool.Win
{
    public partial class MD5TabControl : UserControl
    {
        public event Action<string>? StatusChanged;

        public MD5TabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // ����Ĭ��ѡ��
            comboMD5DataFormat.SelectedIndex = 0; // Text
            comboMD5OutputFormat.SelectedIndex = 0; // Hex
            comboMD5FileHashFormat.SelectedIndex = 0; // Hex
            comboMD5VerifyDataFormat.SelectedIndex = 0; // Text
            comboMD5VerifyHashFormat.SelectedIndex = 0; // Hex

            // ����ʾ������
            textMD5Input.Text = "Hello MD5!";
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region MD5��ϣ����

        private void btnMD5Hash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textMD5Input.Text))
                {
                    MessageBox.Show("������Ҫ�����ϣ�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڼ���MD5��ϣ...");

                string inputData = textMD5Input.Text;
                string dataFormat = comboMD5DataFormat.SelectedItem?.ToString() ?? "Text";
                string outputFormat = comboMD5OutputFormat.SelectedItem?.ToString() ?? "Hex";

                byte[] dataBytes = ConvertInputData(inputData, dataFormat);
                
                var md5Hash = new Md5Hash();
                byte[] hashBytes = md5Hash.ComputeHash(dataBytes);
                string result = ConvertHashToFormat(hashBytes, outputFormat);

                textMD5Output.Text = result;
                SetStatus($"MD5��ϣ������� - �����ʽ��{dataFormat}�������ʽ��{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"MD5��ϣ����ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("MD5��ϣ����ʧ��");
            }
        }

        private void btnMD5Clear_Click(object sender, EventArgs e)
        {
            textMD5Input.Clear();
            textMD5Output.Clear();
            SetStatus("�������������");
        }

        #endregion

        #region MD5�ļ���ϣ

        private void btnMD5SelectFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "ѡ��Ҫ�����ϣ���ļ�";
                    openFileDialog.Filter = "�����ļ� (*.*)|*.*";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        textMD5FilePath.Text = openFileDialog.FileName;
                        SetStatus($"��ѡ���ļ�: {Path.GetFileName(openFileDialog.FileName)}");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"ѡ���ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("ѡ���ļ�ʧ��");
            }
        }

        private void btnMD5ComputeFileHash_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textMD5FilePath.Text) || !File.Exists(textMD5FilePath.Text))
                {
                    MessageBox.Show("����ѡ��һ����Ч���ļ���", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڼ����ļ�MD5��ϣ...");

                string outputFormat = comboMD5FileHashFormat.SelectedItem?.ToString() ?? "Hex";
                
                var md5Hash = new Md5Hash();
                byte[] hashBytes = md5Hash.ComputeFileHash(textMD5FilePath.Text);
                string result = ConvertHashToFormat(hashBytes, outputFormat);

                textMD5FileHash.Text = result;
                SetStatus($"�ļ�MD5��ϣ������� - �����ʽ��{outputFormat}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�����ļ���ϣʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�����ļ���ϣʧ��");
            }
        }

        #endregion

        #region MD5��ϣ��֤

        private void btnMD5Verify_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textMD5VerifyData.Text))
                {
                    MessageBox.Show("������Ҫ��֤�����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (string.IsNullOrEmpty(textMD5VerifyHash.Text))
                {
                    MessageBox.Show("�����������Ĺ�ϣֵ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("������֤MD5��ϣ...");

                string data = textMD5VerifyData.Text;
                string expectedHash = textMD5VerifyHash.Text;
                string dataFormat = comboMD5VerifyDataFormat.SelectedItem?.ToString() ?? "Text";
                string hashFormat = comboMD5VerifyHashFormat.SelectedItem?.ToString() ?? "Hex";

                byte[] dataBytes = ConvertInputData(data, dataFormat);
                byte[] expectedHashBytes = ConvertHashFromFormat(expectedHash, hashFormat);
                
                var md5Hash = new Md5Hash();
                bool isValid = md5Hash.VerifyHash(dataBytes, expectedHashBytes);

                labelMD5VerifyResult.Text = isValid ? "��֤ͨ��" : "��֤ʧ��";
                labelMD5VerifyResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"MD5��ϣ��֤��� - �����{(isValid ? "ͨ��" : "ʧ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"MD5��ϣ��֤ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelMD5VerifyResult.Text = "��֤�쳣";
                labelMD5VerifyResult.ForeColor = Color.Red;
                SetStatus("MD5��ϣ��֤ʧ��");
            }
        }

        #endregion

        #region ��������

        private byte[] ConvertInputData(string data, string format)
        {
            return format switch
            {
                "Text" => Encoding.UTF8.GetBytes(data),
                "Base64" => Convert.FromBase64String(data),
                "Hex" => CryptoUtil.ConvertFromHexString(data),
                _ => Encoding.UTF8.GetBytes(data)
            };
        }

        private string ConvertHashToFormat(byte[] hashBytes, string format)
        {
            return format switch
            {
                "Hex" => CryptoUtil.BytesToHex(hashBytes),
                "Base64" => Convert.ToBase64String(hashBytes),
                _ => CryptoUtil.BytesToHex(hashBytes)
            };
        }

        private byte[] ConvertHashFromFormat(string hashString, string format)
        {
            return format switch
            {
                "Hex" => CryptoUtil.ConvertFromHexString(hashString),
                "Base64" => Convert.FromBase64String(hashString),
                _ => CryptoUtil.ConvertFromHexString(hashString)
            };
        }

        #endregion
    }
}