using CryptoTool.Common;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;

namespace CryptoTool.Win
{
    public partial class RSAConvertTabControl : UserControl
    {
        public event Action<string> StatusChanged;

        // �洢����Ĺ�Կ��˽Կ������֤
        private string _publicKeyForValidation = string.Empty;
        private string _privateKeyForValidation = string.Empty;
        private RSAUtil.RSAKeyFormat _publicKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _publicKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;
        private RSAUtil.RSAKeyFormat _privateKeyFormatForValidation = RSAUtil.RSAKeyFormat.PEM;
        private RSAUtil.RSAKeyType _privateKeyTypeForValidation = RSAUtil.RSAKeyType.PKCS1;

        public RSAConvertTabControl()
        {
            InitializeComponent();
            InitializeDefaults();
        }

        private void InitializeDefaults()
        {
            // ��ʼ��Ĭ��ֵ
            comboInputKeyType.SelectedIndex = 0; // PKCS1
            comboInputFormat.SelectedIndex = 0; // PEM
            comboOutputKeyType.SelectedIndex = 1; // PKCS8
            comboOutputFormat.SelectedIndex = 0; // PEM
            radioPrivateKey.Checked = true; // Ĭ��ѡ��˽Կ

            // ��ʼ����֤�����ǩ
            labelValidationResult.Text = "��֤���: �ȴ���֤";
            labelValidationResult.ForeColor = Color.Gray;
        }

        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #region �¼�����

        private void btnImportFromFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "��Կ�ļ� (*.txt;*.key;*.pem;*.pub)|*.txt;*.key;*.pem;*.pub|�����ļ� (*.*)|*.*";
                    openFileDialog.Title = "����RSA��Կ�ļ�";

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string content = File.ReadAllText(openFileDialog.FileName, Encoding.UTF8);
                        textInputKey.Text = content.Trim();
                        
                        // �����ļ������Զ��ж���Կ����
                        AutoDetectKeyType(content);
                        
                        SetStatus("��Կ�ļ�����ɹ�");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"������Կ�ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("������Կ�ļ�ʧ��");
            }
        }

        private void btnValidateKeyPair_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(_publicKeyForValidation) || string.IsNullOrEmpty(_privateKeyForValidation))
                {
                    MessageBox.Show("���ȷֱ��빫Կ��˽Կ������֤��\n\n�������裺\n1. ����˽Կ���������˽Կ��ȡ��Կ��\n2. ��ֱ��빫Կ��˽Կ�ļ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                SetStatus("������֤��Կ��һ����...");

                bool isValid = RSAUtil.ValidateKeyPair(_publicKeyForValidation, _privateKeyForValidation, 
                    _publicKeyFormatForValidation, _publicKeyTypeForValidation,
                    _privateKeyFormatForValidation, _privateKeyTypeForValidation);

                labelValidationResult.Text = $"��֤���: {(isValid ? "��Կ��ƥ��" : "��Կ�Բ�ƥ��")}";
                labelValidationResult.ForeColor = isValid ? Color.Green : Color.Red;

                SetStatus($"��Կ����֤��� - {(isValid ? "ƥ��" : "��ƥ��")}");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��Կ����֤ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                labelValidationResult.Text = "��֤���: ��֤�쳣";
                labelValidationResult.ForeColor = Color.Red;
                SetStatus("��Կ����֤ʧ��");
            }
        }

        private void btnGetPublicKeyFromPrivate_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("��������˽Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (radioPublicKey.Checked)
                {
                    MessageBox.Show("��ѡ��˽Կ���Ͳ�����ȡ��Կ��", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڴ�˽Կ��ȡ��Կ...");

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                // ���Խ���˽Կ�����ʧ����ʹ�����ܼ��
                AsymmetricKeyParameter? keyParam = SafeParseKey(textInputKey.Text, true, inputFormat, inputKeyType);
                
                if (keyParam == null)
                {
                    // �������ʧ�ܣ��������ܼ��
                    var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, true);
                    keyParam = SafeParseKey(textInputKey.Text, true, detectedFormat, detectedType);
                    
                    if (keyParam != null)
                    {
                        // ����UI��ʾ��⵽�ĸ�ʽ
                        comboInputFormat.SelectedIndex = (int)detectedFormat;
                        comboInputKeyType.SelectedIndex = (int)detectedType;
                        inputFormat = detectedFormat;
                        inputKeyType = detectedType;
                        SetStatus("ʹ�����ܼ�����½���˽Կ�ɹ�");
                    }
                    else
                    {
                        throw new ArgumentException("�޷�����˽Կ��������Կ���ݺ͸�ʽѡ��");
                    }
                }

                var privateKey = (RsaPrivateCrtKeyParameters)keyParam;

                // ��˽Կ��ȡ��Կ����
                var publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);

                // ���ɹ�Կ�ַ���
                string publicKeyString = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);

                textOutputKey.Text = publicKeyString;

                // �洢��Կ������֤
                _privateKeyForValidation = textInputKey.Text;
                _privateKeyFormatForValidation = inputFormat;
                _privateKeyTypeForValidation = inputKeyType;
                _publicKeyForValidation = publicKeyString;
                _publicKeyFormatForValidation = outputFormat;
                _publicKeyTypeForValidation = outputKeyType;

                // �Զ���֤��Կ��
                labelValidationResult.Text = "��֤���: ��Կ��ƥ�䣨��˽Կ��ȡ��";
                labelValidationResult.ForeColor = Color.Green;

                SetStatus("��˽Կ��ȡ��Կ���");
            }
            catch (InvalidCastException ex)
            {
                MessageBox.Show($"��˽Կ��ȡ��Կʧ�ܣ���Կ���Ͳ�ƥ��\n\n��ϸ��Ϣ��{ex.Message}\n\n��ȷ���������˽Կ�����ǹ�Կ", "���ʹ���", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��˽Կ��ȡ��Կʧ�� - ���Ͳ�ƥ��");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��˽Կ��ȡ��Կʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��˽Կ��ȡ��Կʧ��");
            }
        }

        private void btnConvert_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textInputKey.Text))
                {
                    MessageBox.Show("����������Կ���ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                SetStatus("���ڽ��и�ʽת��...");

                var inputKeyType = (RSAUtil.RSAKeyType)comboInputKeyType.SelectedIndex;
                var inputFormat = (RSAUtil.RSAKeyFormat)comboInputFormat.SelectedIndex;
                var outputKeyType = (RSAUtil.RSAKeyType)comboOutputKeyType.SelectedIndex;
                var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;

                bool isPrivateKey = radioPrivateKey.Checked;
                string convertedKey;

                // ����ʹ�ø���ȫ�Ľ�������
                if (isPrivateKey)
                {
                    // ���԰�ȫ����˽Կ
                    var keyParam = SafeParseKey(textInputKey.Text, true, inputFormat, inputKeyType);
                    
                    if (keyParam == null)
                    {
                        // �������ʧ�ܣ��������ܼ��
                        var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, true);
                        keyParam = SafeParseKey(textInputKey.Text, true, detectedFormat, detectedType);
                        
                        if (keyParam != null)
                        {
                            // ����UI��ʾ��⵽�ĸ�ʽ
                            comboInputFormat.SelectedIndex = (int)detectedFormat;
                            comboInputKeyType.SelectedIndex = (int)detectedType;
                            inputFormat = detectedFormat;
                            inputKeyType = detectedType;
                            SetStatus("ʹ�����ܼ�����½�����Կ�ɹ�");
                        }
                        else
                        {
                            throw new ArgumentException("�޷�����˽Կ��������Կ���ݺ͸�ʽѡ��");
                        }
                    }

                    // ȷ������ȷ��˽Կ����
                    if (keyParam is RsaPrivateCrtKeyParameters privateKey)
                    {
                        convertedKey = RSAUtil.GeneratePrivateKeyString(privateKey, outputFormat, outputKeyType);
                    }
                    else
                    {
                        throw new InvalidCastException($"��������Կ���Ͳ�ƥ�䣬����RsaPrivateCrtKeyParameters��ʵ�ʵõ�{keyParam.GetType().Name}");
                    }
                }
                else
                {
                    // ���԰�ȫ������Կ
                    var keyParam = SafeParseKey(textInputKey.Text, false, inputFormat, inputKeyType);
                    
                    if (keyParam == null)
                    {
                        // �������ʧ�ܣ��������ܼ��
                        var (detectedFormat, detectedType) = SmartDetectKeyFormat(textInputKey.Text, false);
                        keyParam = SafeParseKey(textInputKey.Text, false, detectedFormat, detectedType);
                        
                        if (keyParam != null)
                        {
                            // ����UI��ʾ��⵽�ĸ�ʽ
                            comboInputFormat.SelectedIndex = (int)detectedFormat;
                            comboInputKeyType.SelectedIndex = (int)detectedType;
                            inputFormat = detectedFormat;
                            inputKeyType = detectedType;
                            SetStatus("ʹ�����ܼ�����½�����Կ�ɹ�");
                        }
                        else
                        {
                            throw new ArgumentException("�޷�������Կ��������Կ���ݺ͸�ʽѡ��");
                        }
                    }

                    // ȷ������ȷ�Ĺ�Կ����
                    if (keyParam is RsaKeyParameters publicKey)
                    {
                        convertedKey = RSAUtil.GeneratePublicKeyString(publicKey, outputFormat, outputKeyType);
                    }
                    else
                    {
                        throw new InvalidCastException($"��������Կ���Ͳ�ƥ�䣬����RsaKeyParameters��ʵ�ʵõ�{keyParam.GetType().Name}");
                    }
                }

                textOutputKey.Text = convertedKey;
                SetStatus($"��ʽת����� - {inputKeyType}/{inputFormat} -> {outputKeyType}/{outputFormat}");
            }
            catch (InvalidCastException ex)
            {
                MessageBox.Show($"��Կ��ʽת��ʧ�ܣ���Կ���Ͳ�ƥ��\n\n��ϸ��Ϣ��{ex.Message}\n\n���飺\n1. ѡ�����Կ���ͣ���Կ/˽Կ���Ƿ���ȷ\n2. �����ʽ����Կ����ѡ���Ƿ�ƥ��\n3. ����ʹ���Զ���⹦��", "��ʽת������", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��ʽת��ʧ�� - ��Կ���Ͳ�ƥ��");
            }
            catch (ArgumentException ex)
            {
                MessageBox.Show($"��ʽת��ʧ�ܣ�{ex.Message}\n\n���飺\n1. �����Կ�����Ƿ�����\n2. ���Բ�ͬ�������ʽ���\n3. ʹ���Զ���⹦��", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��ʽת��ʧ��");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"��ʽת��ʧ�ܣ�{ex.Message}\n\n�������������ڣ�\n1. �볢�����������������\n2. �����Կ�Ƿ����Կɿ���Դ\n3. ����ʹ���ļ����빦��", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("��ʽת��ʧ��");
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            textInputKey.Clear();
            textOutputKey.Clear();
            labelValidationResult.Text = "��֤���: �ȴ���֤";
            labelValidationResult.ForeColor = Color.Gray;
            _publicKeyForValidation = string.Empty;
            _privateKeyForValidation = string.Empty;
            SetStatus("�������������");
        }

        private void btnSaveToFile_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("û�пɱ�������ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                {
                    var outputFormat = (RSAUtil.RSAKeyFormat)comboOutputFormat.SelectedIndex;
                    var keyType = radioPrivateKey.Checked ? "private" : "public";
                    
                    string extension = outputFormat switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => ".pem",
                        RSAUtil.RSAKeyFormat.Base64 => ".txt",
                        RSAUtil.RSAKeyFormat.Hex => ".txt",
                        _ => ".txt"
                    };

                    saveFileDialog.Filter = GetFileFilter(outputFormat);
                    saveFileDialog.Title = "����ת�������Կ";
                    saveFileDialog.FileName = $"rsa_{keyType}_key{extension}";

                    if (saveFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        File.WriteAllText(saveFileDialog.FileName, textOutputKey.Text, Encoding.UTF8);
                        SetStatus("��Կ�ļ�����ɹ�");
                        MessageBox.Show("��Կ�ļ�����ɹ���", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�����ļ�ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("�����ļ�ʧ��");
            }
        }

        private void btnCopyToClipboard_Click(object sender, EventArgs e)
        {
            try
            {
                if (string.IsNullOrEmpty(textOutputKey.Text))
                {
                    MessageBox.Show("û�пɸ��Ƶ����ݣ�", "��ʾ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                Clipboard.SetText(textOutputKey.Text);
                SetStatus("�Ѹ��Ƶ�������");
                MessageBox.Show("�Ѹ��Ƶ������壡", "�ɹ�", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"���Ƶ�������ʧ�ܣ�{ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                SetStatus("���Ƶ�������ʧ��");
            }
        }

        private void textInputKey_TextChanged(object sender, EventArgs e)
        {
            // ��������Կ���ݸı�ʱ���Զ������Կ����
            if (!string.IsNullOrEmpty(textInputKey.Text))
            {
                AutoDetectKeyType(textInputKey.Text);
            }
            else
            {
                // �����֤���
                labelValidationResult.Text = "��֤���: �ȴ���֤";
                labelValidationResult.ForeColor = Color.Gray;
                _publicKeyForValidation = string.Empty;
                _privateKeyForValidation = string.Empty;
            }
        }

        #endregion

        #region ��������

        private void AutoDetectKeyType(string keyContent)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(keyContent))
                    return;

                bool isPrivateKey = radioPrivateKey.Checked && !radioPublicKey.Checked;

                // ʹ�����ܼ����ȷ����ѵĸ�ʽ���������
                var (detectedFormat, detectedType) = SmartDetectKeyFormat(keyContent, isPrivateKey);

                // ����UIѡ��
                comboInputFormat.SelectedIndex = (int)detectedFormat;
                comboInputKeyType.SelectedIndex = (int)detectedType;

                // �洢�����������֤
                if (isPrivateKey)
                {
                    _privateKeyForValidation = keyContent;
                    _privateKeyFormatForValidation = detectedFormat;
                    _privateKeyTypeForValidation = detectedType;
                }
                else
                {
                    _publicKeyForValidation = keyContent;
                    _publicKeyFormatForValidation = detectedFormat;
                    _publicKeyTypeForValidation = detectedType;
                }

                SetStatus($"��Կ�����Զ����ɹ� - {detectedType}/{detectedFormat}");
            }
            catch
            {
                // �Զ����ʧ��ʱ����Ĭ��ֵ
                SetStatus("�޷��Զ������Կ���ͣ����ֶ�ѡ��");
            }
        }

        private static string GetFileFilter(RSAUtil.RSAKeyFormat format)
        {
            return format switch
            {
                RSAUtil.RSAKeyFormat.PEM => "PEM�ļ� (*.pem)|*.pem|�����ļ� (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Base64 => "�ı��ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*",
                RSAUtil.RSAKeyFormat.Hex => "�ı��ļ� (*.txt)|*.txt|�����ļ� (*.*)|*.*",
                _ => "�����ļ� (*.*)|*.*"
            };
        }

        /// <summary>
        /// ��ȫ�ؽ�����Կ��������ֿ��ܵ��쳣���
        /// </summary>
        /// <param name="keyContent">��Կ����</param>
        /// <param name="isPrivateKey">�Ƿ�Ϊ˽Կ</param>
        /// <param name="format">��Կ��ʽ</param>
        /// <param name="keyType">��Կ����</param>
        /// <returns>���������ʧ��ʱ����null</returns>
        private static AsymmetricKeyParameter? SafeParseKey(string keyContent, bool isPrivateKey, RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType)
        {
            // ���ȳ���ֱ�ӽ�������������ͨ��ParseKey���ܵ���������
            var directResult = DirectParseKey(keyContent, isPrivateKey, format, keyType);
            if (directResult != null)
            {
                // ��֤���ص���Կ�����Ƿ����Ԥ��
                if (isPrivateKey && directResult is RsaPrivateCrtKeyParameters)
                {
                    return directResult;
                }
                else if (!isPrivateKey && directResult is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                {
                    return directResult;
                }
            }

            // ���ֱ�ӽ���ʧ�ܣ�����ͨ��ParseKey����
            try
            {
                AsymmetricKeyParameter result = RSAUtil.ParseKey(keyContent, isPrivateKey, format, keyType);
                
                // ��֤���ص���Կ�����Ƿ����Ԥ��
                if (isPrivateKey)
                {
                    // ����˽Կ��ȷ�����ص���RsaPrivateCrtKeyParameters����
                    if (result is RsaPrivateCrtKeyParameters)
                    {
                        return result;
                    }
                }
                else
                {
                    // ���ڹ�Կ��ȷ�����ص���RsaKeyParameters����
                    if (result is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                    {
                        return result;
                    }
                }
            }
            catch
            {
                // �����쳣������null��ʾ����ʧ��
            }

            return null;
        }

        /// <summary>
        /// ���ܼ����Կ��ʽ�����Զ��ֿ�����
        /// </summary>
        /// <param name="keyContent">��Կ����</param>
        /// <param name="isPrivateKey">�Ƿ�Ϊ˽Կ</param>
        /// <returns>��⵽�ĸ�ʽ������</returns>
        private (RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType) SmartDetectKeyFormat(string keyContent, bool isPrivateKey)
        {
            // �������п��ܵ����
            var combinations = new[]
            {
                (RSAUtil.RSAKeyFormat.PEM, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.PEM, RSAUtil.RSAKeyType.PKCS1),
                (RSAUtil.RSAKeyFormat.Base64, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.Base64, RSAUtil.RSAKeyType.PKCS1),
                (RSAUtil.RSAKeyFormat.Hex, RSAUtil.RSAKeyType.PKCS8),
                (RSAUtil.RSAKeyFormat.Hex, RSAUtil.RSAKeyType.PKCS1)
            };

            // ���ȳ���ֱ�ӽ�������
            foreach (var (format, keyType) in combinations)
            {
                var result = DirectParseKey(keyContent, isPrivateKey, format, keyType);
                if (result != null)
                {
                    // ��֤�������
                    if (isPrivateKey && result is RsaPrivateCrtKeyParameters)
                    {
                        return (format, keyType);
                    }
                    else if (!isPrivateKey && result is RsaKeyParameters rsaKey && !rsaKey.IsPrivate)
                    {
                        return (format, keyType);
                    }
                }
            }

            // ���ֱ�ӽ�����ʧ�ܣ�����SafeParseKey������ͨ��ParseKey�Ļ��ˣ�
            foreach (var (format, keyType) in combinations)
            {
                var result = SafeParseKey(keyContent, isPrivateKey, format, keyType);
                if (result != null)
                {
                    return (format, keyType);
                }
            }

            throw new ArgumentException("�޷������Կ��ʽ��������Կ����");
        }

        /// <summary>
        /// ����ֱ��ʹ��RSAUtil��ר�÷���������Կ������ͨ��ParseKey��������������
        /// </summary>
        /// <param name="keyContent">��Կ����</param>
        /// <param name="isPrivateKey">�Ƿ�Ϊ˽Կ</param>
        /// <param name="format">��Կ��ʽ</param>
        /// <param name="keyType">��Կ����</param>
        /// <returns>���������Կ����</returns>
        private static AsymmetricKeyParameter? DirectParseKey(string keyContent, bool isPrivateKey, RSAUtil.RSAKeyFormat format, RSAUtil.RSAKeyType keyType)
        {
            try
            {
                if (isPrivateKey)
                {
                    return format switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => RSAUtil.ParsePrivateKeyFromPem(keyContent),
                        RSAUtil.RSAKeyFormat.Base64 => RSAUtil.ParsePrivateKeyFromBase64(keyContent, keyType),
                        RSAUtil.RSAKeyFormat.Hex => RSAUtil.ParsePrivateKeyFromHex(keyContent, keyType),
                        _ => null
                    };
                }
                else
                {
                    return format switch
                    {
                        RSAUtil.RSAKeyFormat.PEM => RSAUtil.ParsePublicKeyFromPem(keyContent),
                        RSAUtil.RSAKeyFormat.Base64 => RSAUtil.ParsePublicKeyFromBase64(keyContent, keyType),
                        RSAUtil.RSAKeyFormat.Hex => RSAUtil.ParsePublicKeyFromHex(keyContent, keyType),
                        _ => null
                    };
                }
            }
            catch
            {
                return null;
            }
        }
        #endregion
    }
}