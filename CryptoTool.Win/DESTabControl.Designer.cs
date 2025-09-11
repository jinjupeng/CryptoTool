namespace CryptoTool.Win
{
    partial class DESTabControl : UserControl
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
            groupBoxDESKeys = new GroupBox();
            tableLayoutDESKeys = new TableLayoutPanel();
            panelDESKeyControls = new Panel();
            labelDESKeyFormat = new Label();
            comboDESKeyFormat = new ComboBox();
            btnGenerateDESKey = new Button();
            labelDESKey = new Label();
            panelDESKey = new Panel();
            textDESKey = new TextBox();
            panelDESIVControls = new Panel();
            labelDESIVFormat = new Label();
            comboDESIVFormat = new ComboBox();
            btnGenerateDESIV = new Button();
            labelDESIV = new Label();
            panelDESIV = new Panel();
            textDESIV = new TextBox();
            groupBoxDESEncrypt = new GroupBox();
            tableLayoutDESEncrypt = new TableLayoutPanel();
            panelDESEncryptControls = new Panel();
            btnDecryptFile = new Button();
            btnEncryptFile = new Button();
            btnDESDecrypt = new Button();
            btnDESEncrypt = new Button();
            comboDESCiphertextFormat = new ComboBox();
            labelDESCiphertextFormat = new Label();
            comboDESPlaintextFormat = new ComboBox();
            labelDESPlaintextFormat = new Label();
            comboDESPadding = new ComboBox();
            labelDESPadding = new Label();
            comboDESMode = new ComboBox();
            labelDESMode = new Label();
            labelPlaintext = new Label();
            textDESPlainText = new TextBox();
            labelCiphertext = new Label();
            textDESCipherText = new TextBox();
            mainTableLayout.SuspendLayout();
            groupBoxDESKeys.SuspendLayout();
            tableLayoutDESKeys.SuspendLayout();
            panelDESKeyControls.SuspendLayout();
            panelDESKey.SuspendLayout();
            panelDESIVControls.SuspendLayout();
            panelDESIV.SuspendLayout();
            groupBoxDESEncrypt.SuspendLayout();
            tableLayoutDESEncrypt.SuspendLayout();
            panelDESEncryptControls.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxDESKeys, 0, 0);
            mainTableLayout.Controls.Add(groupBoxDESEncrypt, 0, 1);
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
            // groupBoxDESKeys
            // 
            groupBoxDESKeys.Controls.Add(tableLayoutDESKeys);
            groupBoxDESKeys.Dock = DockStyle.Fill;
            groupBoxDESKeys.Location = new Point(12, 12);
            groupBoxDESKeys.Margin = new Padding(4);
            groupBoxDESKeys.Name = "groupBoxDESKeys";
            groupBoxDESKeys.Padding = new Padding(8);
            groupBoxDESKeys.Size = new Size(1254, 194);
            groupBoxDESKeys.TabIndex = 0;
            groupBoxDESKeys.TabStop = false;
            groupBoxDESKeys.Text = "DES密钥生成";
            // 
            // tableLayoutDESKeys
            // 
            tableLayoutDESKeys.ColumnCount = 1;
            tableLayoutDESKeys.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutDESKeys.Controls.Add(panelDESKeyControls, 0, 0);
            tableLayoutDESKeys.Controls.Add(labelDESKey, 0, 1);
            tableLayoutDESKeys.Controls.Add(panelDESKey, 0, 2);
            tableLayoutDESKeys.Controls.Add(panelDESIVControls, 0, 3);
            tableLayoutDESKeys.Controls.Add(labelDESIV, 0, 4);
            tableLayoutDESKeys.Controls.Add(panelDESIV, 0, 5);
            tableLayoutDESKeys.Dock = DockStyle.Fill;
            tableLayoutDESKeys.Location = new Point(8, 28);
            tableLayoutDESKeys.Name = "tableLayoutDESKeys";
            tableLayoutDESKeys.RowCount = 6;
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 35F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 40F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutDESKeys.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutDESKeys.Size = new Size(1238, 158);
            tableLayoutDESKeys.TabIndex = 0;
            // 
            // panelDESKeyControls
            // 
            panelDESKeyControls.Controls.Add(btnGenerateDESKey);
            panelDESKeyControls.Controls.Add(comboDESKeyFormat);
            panelDESKeyControls.Controls.Add(labelDESKeyFormat);
            panelDESKeyControls.Dock = DockStyle.Fill;
            panelDESKeyControls.Location = new Point(3, 3);
            panelDESKeyControls.Name = "panelDESKeyControls";
            panelDESKeyControls.Size = new Size(1232, 34);
            panelDESKeyControls.TabIndex = 0;
            // 
            // labelDESKeyFormat
            // 
            labelDESKeyFormat.AutoSize = true;
            labelDESKeyFormat.Location = new Point(0, 8);
            labelDESKeyFormat.Margin = new Padding(4, 0, 4, 0);
            labelDESKeyFormat.Name = "labelDESKeyFormat";
            labelDESKeyFormat.Size = new Size(73, 20);
            labelDESKeyFormat.TabIndex = 11;
            labelDESKeyFormat.Text = "密钥格式:";
            // 
            // comboDESKeyFormat
            // 
            comboDESKeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESKeyFormat.FormattingEnabled = true;
            comboDESKeyFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboDESKeyFormat.Location = new Point(80, 4);
            comboDESKeyFormat.Margin = new Padding(4);
            comboDESKeyFormat.Name = "comboDESKeyFormat";
            comboDESKeyFormat.Size = new Size(127, 28);
            comboDESKeyFormat.TabIndex = 10;
            // 
            // btnGenerateDESKey
            // 
            btnGenerateDESKey.Location = new Point(220, 2);
            btnGenerateDESKey.Margin = new Padding(4);
            btnGenerateDESKey.Name = "btnGenerateDESKey";
            btnGenerateDESKey.Size = new Size(103, 30);
            btnGenerateDESKey.TabIndex = 0;
            btnGenerateDESKey.Text = "生成密钥";
            btnGenerateDESKey.UseVisualStyleBackColor = true;
            btnGenerateDESKey.Click += btnGenerateDESKey_Click;
            // 
            // labelDESKey
            // 
            labelDESKey.AutoSize = true;
            labelDESKey.Dock = DockStyle.Bottom;
            labelDESKey.Location = new Point(4, 45);
            labelDESKey.Margin = new Padding(4, 0, 4, 0);
            labelDESKey.Name = "labelDESKey";
            labelDESKey.Size = new Size(1230, 20);
            labelDESKey.TabIndex = 3;
            labelDESKey.Text = "DES密钥:";
            // 
            // panelDESKey
            // 
            panelDESKey.Controls.Add(textDESKey);
            panelDESKey.Dock = DockStyle.Fill;
            panelDESKey.Location = new Point(3, 68);
            panelDESKey.Name = "panelDESKey";
            panelDESKey.Size = new Size(1232, 29);
            panelDESKey.TabIndex = 4;
            // 
            // textDESKey
            // 
            textDESKey.Dock = DockStyle.Fill;
            textDESKey.Location = new Point(0, 0);
            textDESKey.Margin = new Padding(4);
            textDESKey.Name = "textDESKey";
            textDESKey.Size = new Size(1232, 27);
            textDESKey.TabIndex = 2;
            // 
            // panelDESIVControls
            // 
            panelDESIVControls.Controls.Add(btnGenerateDESIV);
            panelDESIVControls.Controls.Add(comboDESIVFormat);
            panelDESIVControls.Controls.Add(labelDESIVFormat);
            panelDESIVControls.Dock = DockStyle.Fill;
            panelDESIVControls.Location = new Point(3, 103);
            panelDESIVControls.Name = "panelDESIVControls";
            panelDESIVControls.Size = new Size(1232, 34);
            panelDESIVControls.TabIndex = 1;
            // 
            // labelDESIVFormat
            // 
            labelDESIVFormat.AutoSize = true;
            labelDESIVFormat.Location = new Point(0, 8);
            labelDESIVFormat.Margin = new Padding(4, 0, 4, 0);
            labelDESIVFormat.Name = "labelDESIVFormat";
            labelDESIVFormat.Size = new Size(73, 20);
            labelDESIVFormat.TabIndex = 11;
            labelDESIVFormat.Text = "向量格式:";
            // 
            // comboDESIVFormat
            // 
            comboDESIVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESIVFormat.FormattingEnabled = true;
            comboDESIVFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboDESIVFormat.Location = new Point(80, 4);
            comboDESIVFormat.Margin = new Padding(4);
            comboDESIVFormat.Name = "comboDESIVFormat";
            comboDESIVFormat.Size = new Size(127, 28);
            comboDESIVFormat.TabIndex = 10;
            // 
            // btnGenerateDESIV
            // 
            btnGenerateDESIV.Location = new Point(220, 2);
            btnGenerateDESIV.Margin = new Padding(4);
            btnGenerateDESIV.Name = "btnGenerateDESIV";
            btnGenerateDESIV.Size = new Size(103, 30);
            btnGenerateDESIV.TabIndex = 1;
            btnGenerateDESIV.Text = "生成向量";
            btnGenerateDESIV.UseVisualStyleBackColor = true;
            btnGenerateDESIV.Click += btnGenerateDESIV_Click;
            // 
            // labelDESIV
            // 
            labelDESIV.AutoSize = true;
            labelDESIV.Dock = DockStyle.Bottom;
            labelDESIV.Location = new Point(4, 145);
            labelDESIV.Margin = new Padding(4, 0, 4, 0);
            labelDESIV.Name = "labelDESIV";
            labelDESIV.Size = new Size(1230, 20);
            labelDESIV.TabIndex = 5;
            labelDESIV.Text = "初始向量:";
            // 
            // panelDESIV
            // 
            panelDESIV.Controls.Add(textDESIV);
            panelDESIV.Dock = DockStyle.Fill;
            panelDESIV.Location = new Point(3, 168);
            panelDESIV.Name = "panelDESIV";
            panelDESIV.Size = new Size(1232, 1);
            panelDESIV.TabIndex = 6;
            // 
            // textDESIV
            // 
            textDESIV.Dock = DockStyle.Fill;
            textDESIV.Location = new Point(0, 0);
            textDESIV.Margin = new Padding(4);
            textDESIV.Name = "textDESIV";
            textDESIV.Size = new Size(1232, 27);
            textDESIV.TabIndex = 4;
            // 
            // groupBoxDESEncrypt
            // 
            groupBoxDESEncrypt.Controls.Add(tableLayoutDESEncrypt);
            groupBoxDESEncrypt.Dock = DockStyle.Fill;
            groupBoxDESEncrypt.Location = new Point(12, 214);
            groupBoxDESEncrypt.Margin = new Padding(4);
            groupBoxDESEncrypt.Name = "groupBoxDESEncrypt";
            groupBoxDESEncrypt.Padding = new Padding(8);
            groupBoxDESEncrypt.Size = new Size(1254, 374);
            groupBoxDESEncrypt.TabIndex = 1;
            groupBoxDESEncrypt.TabStop = false;
            groupBoxDESEncrypt.Text = "DES加密解密";
            // 
            // tableLayoutDESEncrypt
            // 
            tableLayoutDESEncrypt.ColumnCount = 1;
            tableLayoutDESEncrypt.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutDESEncrypt.Controls.Add(panelDESEncryptControls, 0, 0);
            tableLayoutDESEncrypt.Controls.Add(labelPlaintext, 0, 1);
            tableLayoutDESEncrypt.Controls.Add(textDESPlainText, 0, 2);
            tableLayoutDESEncrypt.Controls.Add(labelCiphertext, 0, 3);
            tableLayoutDESEncrypt.Controls.Add(textDESCipherText, 0, 4);
            tableLayoutDESEncrypt.Dock = DockStyle.Fill;
            tableLayoutDESEncrypt.Location = new Point(8, 28);
            tableLayoutDESEncrypt.Name = "tableLayoutDESEncrypt";
            tableLayoutDESEncrypt.RowCount = 5;
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 80F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutDESEncrypt.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutDESEncrypt.Size = new Size(1238, 338);
            tableLayoutDESEncrypt.TabIndex = 0;
            // 
            // panelDESEncryptControls
            // 
            panelDESEncryptControls.Controls.Add(btnDecryptFile);
            panelDESEncryptControls.Controls.Add(btnEncryptFile);
            panelDESEncryptControls.Controls.Add(btnDESDecrypt);
            panelDESEncryptControls.Controls.Add(btnDESEncrypt);
            panelDESEncryptControls.Controls.Add(comboDESCiphertextFormat);
            panelDESEncryptControls.Controls.Add(labelDESCiphertextFormat);
            panelDESEncryptControls.Controls.Add(comboDESPlaintextFormat);
            panelDESEncryptControls.Controls.Add(labelDESPlaintextFormat);
            panelDESEncryptControls.Controls.Add(comboDESPadding);
            panelDESEncryptControls.Controls.Add(labelDESPadding);
            panelDESEncryptControls.Controls.Add(comboDESMode);
            panelDESEncryptControls.Controls.Add(labelDESMode);
            panelDESEncryptControls.Dock = DockStyle.Fill;
            panelDESEncryptControls.Location = new Point(3, 3);
            panelDESEncryptControls.Name = "panelDESEncryptControls";
            panelDESEncryptControls.Size = new Size(1232, 74);
            panelDESEncryptControls.TabIndex = 0;
            // 
            // labelDESMode
            // 
            labelDESMode.AutoSize = true;
            labelDESMode.Location = new Point(0, 8);
            labelDESMode.Margin = new Padding(4, 0, 4, 0);
            labelDESMode.Name = "labelDESMode";
            labelDESMode.Size = new Size(73, 20);
            labelDESMode.TabIndex = 5;
            labelDESMode.Text = "加密模式:";
            // 
            // comboDESMode
            // 
            comboDESMode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESMode.FormattingEnabled = true;
            comboDESMode.Items.AddRange(new object[] { "ECB", "CBC", "CFB", "OFB" });
            comboDESMode.Location = new Point(80, 4);
            comboDESMode.Margin = new Padding(4);
            comboDESMode.Name = "comboDESMode";
            comboDESMode.Size = new Size(127, 28);
            comboDESMode.TabIndex = 4;
            comboDESMode.SelectedIndexChanged += comboDESMode_SelectedIndexChanged;
            // 
            // labelDESPadding
            // 
            labelDESPadding.AutoSize = true;
            labelDESPadding.Location = new Point(220, 8);
            labelDESPadding.Margin = new Padding(4, 0, 4, 0);
            labelDESPadding.Name = "labelDESPadding";
            labelDESPadding.Size = new Size(73, 20);
            labelDESPadding.TabIndex = 7;
            labelDESPadding.Text = "填充模式:";
            // 
            // comboDESPadding
            // 
            comboDESPadding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESPadding.FormattingEnabled = true;
            comboDESPadding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "Zeros", "ISO10126", "ANSIX923", "None" });
            comboDESPadding.Location = new Point(300, 4);
            comboDESPadding.Margin = new Padding(4);
            comboDESPadding.Name = "comboDESPadding";
            comboDESPadding.Size = new Size(127, 28);
            comboDESPadding.TabIndex = 6;
            // 
            // labelDESPlaintextFormat
            // 
            labelDESPlaintextFormat.AutoSize = true;
            labelDESPlaintextFormat.Location = new Point(440, 8);
            labelDESPlaintextFormat.Margin = new Padding(4, 0, 4, 0);
            labelDESPlaintextFormat.Name = "labelDESPlaintextFormat";
            labelDESPlaintextFormat.Size = new Size(73, 20);
            labelDESPlaintextFormat.TabIndex = 11;
            labelDESPlaintextFormat.Text = "明文格式:";
            // 
            // comboDESPlaintextFormat
            // 
            comboDESPlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESPlaintextFormat.FormattingEnabled = true;
            comboDESPlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboDESPlaintextFormat.Location = new Point(520, 4);
            comboDESPlaintextFormat.Margin = new Padding(4);
            comboDESPlaintextFormat.Name = "comboDESPlaintextFormat";
            comboDESPlaintextFormat.Size = new Size(127, 28);
            comboDESPlaintextFormat.TabIndex = 10;
            // 
            // labelDESCiphertextFormat
            // 
            labelDESCiphertextFormat.AutoSize = true;
            labelDESCiphertextFormat.Location = new Point(660, 8);
            labelDESCiphertextFormat.Margin = new Padding(4, 0, 4, 0);
            labelDESCiphertextFormat.Name = "labelDESCiphertextFormat";
            labelDESCiphertextFormat.Size = new Size(73, 20);
            labelDESCiphertextFormat.TabIndex = 9;
            labelDESCiphertextFormat.Text = "密文格式:";
            // 
            // comboDESCiphertextFormat
            // 
            comboDESCiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboDESCiphertextFormat.FormattingEnabled = true;
            comboDESCiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboDESCiphertextFormat.Location = new Point(740, 4);
            comboDESCiphertextFormat.Margin = new Padding(4);
            comboDESCiphertextFormat.Name = "comboDESCiphertextFormat";
            comboDESCiphertextFormat.Size = new Size(127, 28);
            comboDESCiphertextFormat.TabIndex = 8;
            // 
            // btnDESEncrypt
            // 
            btnDESEncrypt.Location = new Point(880, 2);
            btnDESEncrypt.Margin = new Padding(4);
            btnDESEncrypt.Name = "btnDESEncrypt";
            btnDESEncrypt.Size = new Size(80, 30);
            btnDESEncrypt.TabIndex = 0;
            btnDESEncrypt.Text = "加密";
            btnDESEncrypt.UseVisualStyleBackColor = true;
            btnDESEncrypt.Click += btnDESEncrypt_Click;
            // 
            // btnDESDecrypt
            // 
            btnDESDecrypt.Location = new Point(970, 2);
            btnDESDecrypt.Margin = new Padding(4);
            btnDESDecrypt.Name = "btnDESDecrypt";
            btnDESDecrypt.Size = new Size(80, 30);
            btnDESDecrypt.TabIndex = 1;
            btnDESDecrypt.Text = "解密";
            btnDESDecrypt.UseVisualStyleBackColor = true;
            btnDESDecrypt.Click += btnDESDecrypt_Click;
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
            // textDESPlainText
            // 
            textDESPlainText.Dock = DockStyle.Fill;
            textDESPlainText.Location = new Point(4, 109);
            textDESPlainText.Margin = new Padding(4);
            textDESPlainText.Multiline = true;
            textDESPlainText.Name = "textDESPlainText";
            textDESPlainText.ScrollBars = ScrollBars.Both;
            textDESPlainText.Size = new Size(1230, 96);
            textDESPlainText.TabIndex = 2;
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
            // textDESCipherText
            // 
            textDESCipherText.Dock = DockStyle.Fill;
            textDESCipherText.Location = new Point(4, 258);
            textDESCipherText.Margin = new Padding(4);
            textDESCipherText.Multiline = true;
            textDESCipherText.Name = "textDESCipherText";
            textDESCipherText.ScrollBars = ScrollBars.Both;
            textDESCipherText.Size = new Size(1230, 96);
            textDESCipherText.TabIndex = 3;
            // 
            // DESTabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Margin = new Padding(4);
            Name = "DESTabControl";
            Size = new Size(1278, 600);
            mainTableLayout.ResumeLayout(false);
            groupBoxDESKeys.ResumeLayout(false);
            tableLayoutDESKeys.ResumeLayout(false);
            tableLayoutDESKeys.PerformLayout();
            panelDESKeyControls.ResumeLayout(false);
            panelDESKeyControls.PerformLayout();
            panelDESKey.ResumeLayout(false);
            panelDESKey.PerformLayout();
            panelDESIVControls.ResumeLayout(false);
            panelDESIVControls.PerformLayout();
            panelDESIV.ResumeLayout(false);
            panelDESIV.PerformLayout();
            groupBoxDESEncrypt.ResumeLayout(false);
            tableLayoutDESEncrypt.ResumeLayout(false);
            tableLayoutDESEncrypt.PerformLayout();
            panelDESEncryptControls.ResumeLayout(false);
            panelDESEncryptControls.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxDESKeys;
        private TableLayoutPanel tableLayoutDESKeys;
        private Panel panelDESKeyControls;
        private Label labelDESKeyFormat;
        private ComboBox comboDESKeyFormat;
        private Button btnGenerateDESKey;
        private Label labelDESKey;
        private Panel panelDESKey;
        private TextBox textDESKey;
        private Panel panelDESIVControls;
        private Label labelDESIVFormat;
        private ComboBox comboDESIVFormat;
        private Button btnGenerateDESIV;
        private Label labelDESIV;
        private Panel panelDESIV;
        private TextBox textDESIV;
        private GroupBox groupBoxDESEncrypt;
        private TableLayoutPanel tableLayoutDESEncrypt;
        private Panel panelDESEncryptControls;
        private Button btnDecryptFile;
        private Button btnEncryptFile;
        private Button btnDESDecrypt;
        private Button btnDESEncrypt;
        private ComboBox comboDESCiphertextFormat;
        private Label labelDESCiphertextFormat;
        private ComboBox comboDESPlaintextFormat;
        private Label labelDESPlaintextFormat;
        private ComboBox comboDESPadding;
        private Label labelDESPadding;
        private ComboBox comboDESMode;
        private Label labelDESMode;
        private Label labelPlaintext;
        private TextBox textDESPlainText;
        private Label labelCiphertext;
        private TextBox textDESCipherText;
    }
}
