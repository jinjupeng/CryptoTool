namespace CryptoTool.Win
{
    partial class AESTabControl : UserControl
    {
        /// <summary> 
        /// 必需的设计器变量。
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// 清理所有正在使用的资源。
        /// </summary>
        /// <param name="disposing">如果应释放托管资源，为 true；否则为 false。</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region 组件设计器生成的代码

        /// <summary> 
        /// 设计器支持所需的方法 - 不要修改
        /// 使用代码编辑器修改此方法的内容。
        /// </summary>
        private void InitializeComponent()
        {
            mainTableLayout = new TableLayoutPanel();
            groupBoxAESKeys = new GroupBox();
            tableLayoutAESKeys = new TableLayoutPanel();
            panelAESKeyControls = new Panel();
            labelAESKeySize = new Label();
            comboAESKeySize = new ComboBox();
            labelAESKeyFormat = new Label();
            comboAESKeyFormat = new ComboBox();
            btnGenerateAESKey = new Button();
            labelAESKey = new Label();
            panelAESKey = new Panel();
            textAESKey = new TextBox();
            panelAESIVControls = new Panel();
            labelAESIVFormat = new Label();
            comboAESIVFormat = new ComboBox();
            btnGenerateAESIV = new Button();
            labelAESIV = new Label();
            panelAESIV = new Panel();
            textAESIV = new TextBox();
            groupBoxAESEncrypt = new GroupBox();
            tableLayoutAESEncrypt = new TableLayoutPanel();
            panelAESEncryptControls = new Panel();
            btnDecryptFile = new Button();
            btnEncryptFile = new Button();
            btnAESDecrypt = new Button();
            btnAESEncrypt = new Button();
            comboAESCiphertextFormat = new ComboBox();
            labelAESCiphertextFormat = new Label();
            comboAESPlaintextFormat = new ComboBox();
            labelAESPlaintextFormat = new Label();
            comboAESPadding = new ComboBox();
            labelAESPadding = new Label();
            comboAESMode = new ComboBox();
            labelAESMode = new Label();
            labelPlaintext = new Label();
            textAESPlainText = new TextBox();
            labelCiphertext = new Label();
            textAESCipherText = new TextBox();
            mainTableLayout.SuspendLayout();
            groupBoxAESKeys.SuspendLayout();
            tableLayoutAESKeys.SuspendLayout();
            panelAESKeyControls.SuspendLayout();
            panelAESKey.SuspendLayout();
            panelAESIVControls.SuspendLayout();
            panelAESIV.SuspendLayout();
            groupBoxAESEncrypt.SuspendLayout();
            tableLayoutAESEncrypt.SuspendLayout();
            panelAESEncryptControls.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxAESKeys, 0, 0);
            mainTableLayout.Controls.Add(groupBoxAESEncrypt, 0, 1);
            mainTableLayout.Dock = DockStyle.Fill;
            mainTableLayout.Location = new Point(0, 0);
            mainTableLayout.Margin = new Padding(4);
            mainTableLayout.Name = "mainTableLayout";
            mainTableLayout.Padding = new Padding(8);
            mainTableLayout.RowCount = 2;
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 35F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 65F));
            mainTableLayout.Size = new Size(1278, 600);
            mainTableLayout.TabIndex = 0;
            // 
            // groupBoxAESKeys
            // 
            groupBoxAESKeys.Controls.Add(tableLayoutAESKeys);
            groupBoxAESKeys.Dock = DockStyle.Fill;
            groupBoxAESKeys.Location = new Point(12, 12);
            groupBoxAESKeys.Margin = new Padding(4);
            groupBoxAESKeys.Name = "groupBoxAESKeys";
            groupBoxAESKeys.Padding = new Padding(8);
            groupBoxAESKeys.Size = new Size(1254, 194);
            groupBoxAESKeys.TabIndex = 0;
            groupBoxAESKeys.TabStop = false;
            groupBoxAESKeys.Text = "AES密钥生成";
            // 
            // tableLayoutAESKeys
            // 
            tableLayoutAESKeys.ColumnCount = 1;
            tableLayoutAESKeys.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutAESKeys.Controls.Add(panelAESKeyControls, 0, 0);
            tableLayoutAESKeys.Controls.Add(labelAESKey, 0, 1);
            tableLayoutAESKeys.Controls.Add(panelAESKey, 0, 2);
            tableLayoutAESKeys.Controls.Add(panelAESIVControls, 0, 3);
            tableLayoutAESKeys.Controls.Add(labelAESIV, 0, 4);
            tableLayoutAESKeys.Controls.Add(panelAESIV, 0, 5);
            tableLayoutAESKeys.Dock = DockStyle.Fill;
            tableLayoutAESKeys.Location = new Point(8, 28);
            tableLayoutAESKeys.Name = "tableLayoutAESKeys";
            tableLayoutAESKeys.RowCount = 6;
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 35F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutAESKeys.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutAESKeys.Size = new Size(1238, 158);
            tableLayoutAESKeys.TabIndex = 0;
            // 
            // panelAESKeyControls
            // 
            panelAESKeyControls.Controls.Add(btnGenerateAESKey);
            panelAESKeyControls.Controls.Add(comboAESKeyFormat);
            panelAESKeyControls.Controls.Add(labelAESKeyFormat);
            panelAESKeyControls.Controls.Add(comboAESKeySize);
            panelAESKeyControls.Controls.Add(labelAESKeySize);
            panelAESKeyControls.Dock = DockStyle.Fill;
            panelAESKeyControls.Location = new Point(3, 3);
            panelAESKeyControls.Name = "panelAESKeyControls";
            panelAESKeyControls.Size = new Size(1232, 34);
            panelAESKeyControls.TabIndex = 0;
            // 
            // labelAESKeySize
            // 
            labelAESKeySize.AutoSize = true;
            labelAESKeySize.Location = new Point(0, 8);
            labelAESKeySize.Margin = new Padding(4, 0, 4, 0);
            labelAESKeySize.Name = "labelAESKeySize";
            labelAESKeySize.Size = new Size(73, 20);
            labelAESKeySize.TabIndex = 9;
            labelAESKeySize.Text = "密钥长度:";
            // 
            // comboAESKeySize
            // 
            comboAESKeySize.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESKeySize.FormattingEnabled = true;
            comboAESKeySize.Items.AddRange(new object[] { "AES128", "AES192", "AES256" });
            comboAESKeySize.Location = new Point(80, 4);
            comboAESKeySize.Margin = new Padding(4);
            comboAESKeySize.Name = "comboAESKeySize";
            comboAESKeySize.Size = new Size(127, 28);
            comboAESKeySize.TabIndex = 8;
            // 
            // labelAESKeyFormat
            // 
            labelAESKeyFormat.AutoSize = true;
            labelAESKeyFormat.Location = new Point(220, 8);
            labelAESKeyFormat.Margin = new Padding(4, 0, 4, 0);
            labelAESKeyFormat.Name = "labelAESKeyFormat";
            labelAESKeyFormat.Size = new Size(73, 20);
            labelAESKeyFormat.TabIndex = 11;
            labelAESKeyFormat.Text = "密钥格式:";
            // 
            // comboAESKeyFormat
            // 
            comboAESKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESKeyFormat.FormattingEnabled = true;
            comboAESKeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESKeyFormat.Location = new Point(300, 4);
            comboAESKeyFormat.Margin = new Padding(4);
            comboAESKeyFormat.Name = "comboAESKeyFormat";
            comboAESKeyFormat.Size = new Size(127, 28);
            comboAESKeyFormat.TabIndex = 10;
            // 
            // btnGenerateAESKey
            // 
            btnGenerateAESKey.Location = new Point(440, 2);
            btnGenerateAESKey.Margin = new Padding(4);
            btnGenerateAESKey.Name = "btnGenerateAESKey";
            btnGenerateAESKey.Size = new Size(103, 30);
            btnGenerateAESKey.TabIndex = 0;
            btnGenerateAESKey.Text = "生成密钥";
            btnGenerateAESKey.UseVisualStyleBackColor = true;
            btnGenerateAESKey.Click += btnGenerateAESKey_Click;
            // 
            // labelAESKey
            // 
            labelAESKey.AutoSize = true;
            labelAESKey.Dock = DockStyle.Bottom;
            labelAESKey.Location = new Point(4, 45);
            labelAESKey.Margin = new Padding(4, 0, 4, 0);
            labelAESKey.Name = "labelAESKey";
            labelAESKey.Size = new Size(1230, 20);
            labelAESKey.TabIndex = 3;
            labelAESKey.Text = "AES密钥:";
            // 
            // panelAESKey
            // 
            panelAESKey.Controls.Add(textAESKey);
            panelAESKey.Dock = DockStyle.Fill;
            panelAESKey.Location = new Point(3, 68);
            panelAESKey.Name = "panelAESKey";
            panelAESKey.Size = new Size(1232, 29);
            panelAESKey.TabIndex = 4;
            // 
            // textAESKey
            // 
            textAESKey.Dock = DockStyle.Fill;
            textAESKey.Location = new Point(0, 0);
            textAESKey.Margin = new Padding(4);
            textAESKey.Name = "textAESKey";
            textAESKey.Size = new Size(1232, 27);
            textAESKey.TabIndex = 2;
            // 
            // panelAESIVControls
            // 
            panelAESIVControls.Controls.Add(btnGenerateAESIV);
            panelAESIVControls.Controls.Add(comboAESIVFormat);
            panelAESIVControls.Controls.Add(labelAESIVFormat);
            panelAESIVControls.Dock = DockStyle.Fill;
            panelAESIVControls.Location = new Point(3, 103);
            panelAESIVControls.Name = "panelAESIVControls";
            panelAESIVControls.Size = new Size(1232, 34);
            panelAESIVControls.TabIndex = 1;
            // 
            // labelAESIVFormat
            // 
            labelAESIVFormat.AutoSize = true;
            labelAESIVFormat.Location = new Point(0, 8);
            labelAESIVFormat.Margin = new Padding(4, 0, 4, 0);
            labelAESIVFormat.Name = "labelAESIVFormat";
            labelAESIVFormat.Size = new Size(73, 20);
            labelAESIVFormat.TabIndex = 11;
            labelAESIVFormat.Text = "向量格式:";
            // 
            // comboAESIVFormat
            // 
            comboAESIVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESIVFormat.FormattingEnabled = true;
            comboAESIVFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESIVFormat.Location = new Point(80, 4);
            comboAESIVFormat.Margin = new Padding(4);
            comboAESIVFormat.Name = "comboAESIVFormat";
            comboAESIVFormat.Size = new Size(127, 28);
            comboAESIVFormat.TabIndex = 10;
            // 
            // btnGenerateAESIV
            // 
            btnGenerateAESIV.Location = new Point(220, 2);
            btnGenerateAESIV.Margin = new Padding(4);
            btnGenerateAESIV.Name = "btnGenerateAESIV";
            btnGenerateAESIV.Size = new Size(103, 30);
            btnGenerateAESIV.TabIndex = 1;
            btnGenerateAESIV.Text = "生成向量";
            btnGenerateAESIV.UseVisualStyleBackColor = true;
            btnGenerateAESIV.Click += btnGenerateAESIV_Click;
            // 
            // labelAESIV
            // 
            labelAESIV.AutoSize = true;
            labelAESIV.Dock = DockStyle.Bottom;
            labelAESIV.Location = new Point(4, 145);
            labelAESIV.Margin = new Padding(4, 0, 4, 0);
            labelAESIV.Name = "labelAESIV";
            labelAESIV.Size = new Size(1230, 20);
            labelAESIV.TabIndex = 5;
            labelAESIV.Text = "初始向量:";
            // 
            // panelAESIV
            // 
            panelAESIV.Controls.Add(textAESIV);
            panelAESIV.Dock = DockStyle.Fill;
            panelAESIV.Location = new Point(3, 168);
            panelAESIV.Name = "panelAESIV";
            panelAESIV.Size = new Size(1232, 1);
            panelAESIV.TabIndex = 6;
            // 
            // textAESIV
            // 
            textAESIV.Dock = DockStyle.Fill;
            textAESIV.Location = new Point(0, 0);
            textAESIV.Margin = new Padding(4);
            textAESIV.Name = "textAESIV";
            textAESIV.Size = new Size(1232, 27);
            textAESIV.TabIndex = 4;
            // 
            // groupBoxAESEncrypt
            // 
            groupBoxAESEncrypt.Controls.Add(tableLayoutAESEncrypt);
            groupBoxAESEncrypt.Dock = DockStyle.Fill;
            groupBoxAESEncrypt.Location = new Point(12, 214);
            groupBoxAESEncrypt.Margin = new Padding(4);
            groupBoxAESEncrypt.Name = "groupBoxAESEncrypt";
            groupBoxAESEncrypt.Padding = new Padding(8);
            groupBoxAESEncrypt.Size = new Size(1254, 374);
            groupBoxAESEncrypt.TabIndex = 1;
            groupBoxAESEncrypt.TabStop = false;
            groupBoxAESEncrypt.Text = "AES加密解密";
            // 
            // tableLayoutAESEncrypt
            // 
            tableLayoutAESEncrypt.ColumnCount = 1;
            tableLayoutAESEncrypt.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutAESEncrypt.Controls.Add(panelAESEncryptControls, 0, 0);
            tableLayoutAESEncrypt.Controls.Add(labelPlaintext, 0, 1);
            tableLayoutAESEncrypt.Controls.Add(textAESPlainText, 0, 2);
            tableLayoutAESEncrypt.Controls.Add(labelCiphertext, 0, 3);
            tableLayoutAESEncrypt.Controls.Add(textAESCipherText, 0, 4);
            tableLayoutAESEncrypt.Dock = DockStyle.Fill;
            tableLayoutAESEncrypt.Location = new Point(8, 28);
            tableLayoutAESEncrypt.Name = "tableLayoutAESEncrypt";
            tableLayoutAESEncrypt.RowCount = 5;
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 80F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutAESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutAESEncrypt.Size = new Size(1238, 338);
            tableLayoutAESEncrypt.TabIndex = 0;
            // 
            // panelAESEncryptControls
            // 
            panelAESEncryptControls.Controls.Add(btnDecryptFile);
            panelAESEncryptControls.Controls.Add(btnEncryptFile);
            panelAESEncryptControls.Controls.Add(btnAESDecrypt);
            panelAESEncryptControls.Controls.Add(btnAESEncrypt);
            panelAESEncryptControls.Controls.Add(comboAESCiphertextFormat);
            panelAESEncryptControls.Controls.Add(labelAESCiphertextFormat);
            panelAESEncryptControls.Controls.Add(comboAESPlaintextFormat);
            panelAESEncryptControls.Controls.Add(labelAESPlaintextFormat);
            panelAESEncryptControls.Controls.Add(comboAESPadding);
            panelAESEncryptControls.Controls.Add(labelAESPadding);
            panelAESEncryptControls.Controls.Add(comboAESMode);
            panelAESEncryptControls.Controls.Add(labelAESMode);
            panelAESEncryptControls.Dock = DockStyle.Fill;
            panelAESEncryptControls.Location = new Point(3, 3);
            panelAESEncryptControls.Name = "panelAESEncryptControls";
            panelAESEncryptControls.Size = new Size(1232, 74);
            panelAESEncryptControls.TabIndex = 0;
            // 
            // labelAESMode
            // 
            labelAESMode.AutoSize = true;
            labelAESMode.Location = new Point(0, 8);
            labelAESMode.Margin = new Padding(4, 0, 4, 0);
            labelAESMode.Name = "labelAESMode";
            labelAESMode.Size = new Size(73, 20);
            labelAESMode.TabIndex = 5;
            labelAESMode.Text = "加密模式:";
            // 
            // comboAESMode
            // 
            comboAESMode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESMode.FormattingEnabled = true;
            comboAESMode.Items.AddRange(new object[] { "ECB", "CBC", "CFB", "OFB" });
            comboAESMode.Location = new Point(80, 4);
            comboAESMode.Margin = new Padding(4);
            comboAESMode.Name = "comboAESMode";
            comboAESMode.Size = new Size(127, 28);
            comboAESMode.TabIndex = 4;
            comboAESMode.SelectedIndexChanged += comboAESMode_SelectedIndexChanged;
            // 
            // labelAESPadding
            // 
            labelAESPadding.AutoSize = true;
            labelAESPadding.Location = new Point(220, 8);
            labelAESPadding.Margin = new Padding(4, 0, 4, 0);
            labelAESPadding.Name = "labelAESPadding";
            labelAESPadding.Size = new Size(73, 20);
            labelAESPadding.TabIndex = 7;
            labelAESPadding.Text = "填充模式:";
            // 
            // comboAESPadding
            // 
            comboAESPadding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESPadding.FormattingEnabled = true;
            comboAESPadding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "Zeros", "ISO10126", "ANSIX923", "None" });
            comboAESPadding.Location = new Point(300, 4);
            comboAESPadding.Margin = new Padding(4);
            comboAESPadding.Name = "comboAESPadding";
            comboAESPadding.Size = new Size(127, 28);
            comboAESPadding.TabIndex = 6;
            // 
            // labelAESPlaintextFormat
            // 
            labelAESPlaintextFormat.AutoSize = true;
            labelAESPlaintextFormat.Location = new Point(440, 8);
            labelAESPlaintextFormat.Margin = new Padding(4, 0, 4, 0);
            labelAESPlaintextFormat.Name = "labelAESPlaintextFormat";
            labelAESPlaintextFormat.Size = new Size(73, 20);
            labelAESPlaintextFormat.TabIndex = 11;
            labelAESPlaintextFormat.Text = "明文格式:";
            // 
            // comboAESPlaintextFormat
            // 
            comboAESPlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESPlaintextFormat.FormattingEnabled = true;
            comboAESPlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboAESPlaintextFormat.Location = new Point(520, 4);
            comboAESPlaintextFormat.Margin = new Padding(4);
            comboAESPlaintextFormat.Name = "comboAESPlaintextFormat";
            comboAESPlaintextFormat.Size = new Size(127, 28);
            comboAESPlaintextFormat.TabIndex = 10;
            // 
            // labelAESCiphertextFormat
            // 
            labelAESCiphertextFormat.AutoSize = true;
            labelAESCiphertextFormat.Location = new Point(660, 8);
            labelAESCiphertextFormat.Margin = new Padding(4, 0, 4, 0);
            labelAESCiphertextFormat.Name = "labelAESCiphertextFormat";
            labelAESCiphertextFormat.Size = new Size(73, 20);
            labelAESCiphertextFormat.TabIndex = 9;
            labelAESCiphertextFormat.Text = "密文格式:";
            // 
            // comboAESCiphertextFormat
            // 
            comboAESCiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboAESCiphertextFormat.FormattingEnabled = true;
            comboAESCiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboAESCiphertextFormat.Location = new Point(740, 4);
            comboAESCiphertextFormat.Margin = new Padding(4);
            comboAESCiphertextFormat.Name = "comboAESCiphertextFormat";
            comboAESCiphertextFormat.Size = new Size(127, 28);
            comboAESCiphertextFormat.TabIndex = 8;
            // 
            // btnAESEncrypt
            // 
            btnAESEncrypt.Location = new Point(880, 2);
            btnAESEncrypt.Margin = new Padding(4);
            btnAESEncrypt.Name = "btnAESEncrypt";
            btnAESEncrypt.Size = new Size(80, 30);
            btnAESEncrypt.TabIndex = 0;
            btnAESEncrypt.Text = "加密";
            btnAESEncrypt.UseVisualStyleBackColor = true;
            btnAESEncrypt.Click += btnAESEncrypt_Click;
            // 
            // btnAESDecrypt
            // 
            btnAESDecrypt.Location = new Point(970, 2);
            btnAESDecrypt.Margin = new Padding(4);
            btnAESDecrypt.Name = "btnAESDecrypt";
            btnAESDecrypt.Size = new Size(80, 30);
            btnAESDecrypt.TabIndex = 1;
            btnAESDecrypt.Text = "解密";
            btnAESDecrypt.UseVisualStyleBackColor = true;
            btnAESDecrypt.Click += btnAESDecrypt_Click;
            // 
            // btnEncryptFile
            // 
            btnEncryptFile.Location = new Point(880, 40);
            btnEncryptFile.Margin = new Padding(4);
            btnEncryptFile.Name = "btnEncryptFile";
            btnEncryptFile.Size = new Size(80, 30);
            btnEncryptFile.TabIndex = 2;
            btnEncryptFile.Text = "加密文件";
            btnEncryptFile.UseVisualStyleBackColor = true;
            btnEncryptFile.Click += btnEncryptFile_Click;
            // 
            // btnDecryptFile
            // 
            btnDecryptFile.Location = new Point(970, 40);
            btnDecryptFile.Margin = new Padding(4);
            btnDecryptFile.Name = "btnDecryptFile";
            btnDecryptFile.Size = new Size(80, 30);
            btnDecryptFile.TabIndex = 3;
            btnDecryptFile.Text = "解密文件";
            btnDecryptFile.UseVisualStyleBackColor = true;
            btnDecryptFile.Click += btnDecryptFile_Click;
            // 
            // labelPlaintext
            // 
            labelPlaintext.AutoSize = true;
            labelPlaintext.Dock = DockStyle.Bottom;
            labelPlaintext.Location = new Point(4, 85);
            labelPlaintext.Margin = new Padding(4, 0, 4, 0);
            labelPlaintext.Name = "labelPlaintext";
            labelPlaintext.Size = new Size(1230, 20);
            labelPlaintext.TabIndex = 3;
            labelPlaintext.Text = "明文:";
            // 
            // textAESPlainText
            // 
            textAESPlainText.Dock = DockStyle.Fill;
            textAESPlainText.Location = new Point(4, 109);
            textAESPlainText.Margin = new Padding(4);
            textAESPlainText.Multiline = true;
            textAESPlainText.Name = "textAESPlainText";
            textAESPlainText.ScrollBars = ScrollBars.Both;
            textAESPlainText.Size = new Size(1230, 96);
            textAESPlainText.TabIndex = 2;
            // 
            // labelCiphertext
            // 
            labelCiphertext.AutoSize = true;
            labelCiphertext.Dock = DockStyle.Bottom;
            labelCiphertext.Location = new Point(4, 234);
            labelCiphertext.Margin = new Padding(4, 0, 4, 0);
            labelCiphertext.Name = "labelCiphertext";
            labelCiphertext.Size = new Size(1230, 20);
            labelCiphertext.TabIndex = 5;
            labelCiphertext.Text = "密文:";
            // 
            // textAESCipherText
            // 
            textAESCipherText.Dock = DockStyle.Fill;
            textAESCipherText.Location = new Point(4, 258);
            textAESCipherText.Margin = new Padding(4);
            textAESCipherText.Multiline = true;
            textAESCipherText.Name = "textAESCipherText";
            textAESCipherText.ScrollBars = ScrollBars.Both;
            textAESCipherText.Size = new Size(1230, 96);
            textAESCipherText.TabIndex = 3;
            // 
            // AESTabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Margin = new Padding(4);
            Name = "AESTabControl";
            Size = new Size(1278, 600);
            mainTableLayout.ResumeLayout(false);
            groupBoxAESKeys.ResumeLayout(false);
            tableLayoutAESKeys.ResumeLayout(false);
            tableLayoutAESKeys.PerformLayout();
            panelAESKeyControls.ResumeLayout(false);
            panelAESKeyControls.PerformLayout();
            panelAESKey.ResumeLayout(false);
            panelAESKey.PerformLayout();
            panelAESIVControls.ResumeLayout(false);
            panelAESIVControls.PerformLayout();
            panelAESIV.ResumeLayout(false);
            panelAESIV.PerformLayout();
            groupBoxAESEncrypt.ResumeLayout(false);
            tableLayoutAESEncrypt.ResumeLayout(false);
            tableLayoutAESEncrypt.PerformLayout();
            panelAESEncryptControls.ResumeLayout(false);
            panelAESEncryptControls.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxAESKeys;
        private TableLayoutPanel tableLayoutAESKeys;
        private Panel panelAESKeyControls;
        private Label labelAESKeySize;
        private ComboBox comboAESKeySize;
        private Label labelAESKeyFormat;
        private ComboBox comboAESKeyFormat;
        private Button btnGenerateAESKey;
        private Label labelAESKey;
        private Panel panelAESKey;
        private TextBox textAESKey;
        private Panel panelAESIVControls;
        private Label labelAESIVFormat;
        private ComboBox comboAESIVFormat;
        private Button btnGenerateAESIV;
        private Label labelAESIV;
        private Panel panelAESIV;
        private TextBox textAESIV;
        private GroupBox groupBoxAESEncrypt;
        private TableLayoutPanel tableLayoutAESEncrypt;
        private Panel panelAESEncryptControls;
        private Button btnDecryptFile;
        private Button btnEncryptFile;
        private Button btnAESDecrypt;
        private Button btnAESEncrypt;
        private ComboBox comboAESCiphertextFormat;
        private Label labelAESCiphertextFormat;
        private ComboBox comboAESPlaintextFormat;
        private Label labelAESPlaintextFormat;
        private ComboBox comboAESPadding;
        private Label labelAESPadding;
        private ComboBox comboAESMode;
        private Label labelAESMode;
        private Label labelPlaintext;
        private TextBox textAESPlainText;
        private Label labelCiphertext;
        private TextBox textAESCipherText;
    }
}