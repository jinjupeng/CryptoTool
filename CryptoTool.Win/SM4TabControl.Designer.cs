namespace CryptoTool.Win
{
    partial class SM4TabControl : UserControl
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
            groupBoxSM4Encrypt = new GroupBox();
            labelSM4CiphertextFormat = new Label();
            comboSM4CiphertextFormat = new ComboBox();
            labelSM4PlaintextFormat = new Label();
            comboSM4PlaintextFormat = new ComboBox();
            label15 = new Label();
            comboSM4Padding = new ComboBox();
            label14 = new Label();
            comboSM4Mode = new ComboBox();
            label13 = new Label();
            textSM4CipherText = new TextBox();
            label12 = new Label();
            textSM4PlainText = new TextBox();
            btnSM4Decrypt = new Button();
            btnSM4Encrypt = new Button();
            groupBoxSM4Keys = new GroupBox();
            labelSM4IVFormat = new Label();
            comboSM4IVFormat = new ComboBox();
            labelSM4KeyFormat = new Label();
            comboSM4KeyFormat = new ComboBox();
            label11 = new Label();
            textSM4IV = new TextBox();
            label10 = new Label();
            textSM4Key = new TextBox();
            btnGenerateSM4IV = new Button();
            btnGenerateSM4Key = new Button();
            groupBoxSM4Encrypt.SuspendLayout();
            groupBoxSM4Keys.SuspendLayout();
            SuspendLayout();
            // 
            // groupBoxSM4Encrypt
            // 
            groupBoxSM4Encrypt.Controls.Add(labelSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4CiphertextFormat);
            groupBoxSM4Encrypt.Controls.Add(labelSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(comboSM4PlaintextFormat);
            groupBoxSM4Encrypt.Controls.Add(label15);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Padding);
            groupBoxSM4Encrypt.Controls.Add(label14);
            groupBoxSM4Encrypt.Controls.Add(comboSM4Mode);
            groupBoxSM4Encrypt.Controls.Add(label13);
            groupBoxSM4Encrypt.Controls.Add(textSM4CipherText);
            groupBoxSM4Encrypt.Controls.Add(label12);
            groupBoxSM4Encrypt.Controls.Add(textSM4PlainText);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Decrypt);
            groupBoxSM4Encrypt.Controls.Add(btnSM4Encrypt);
            groupBoxSM4Encrypt.Location = new Point(8, 188);
            groupBoxSM4Encrypt.Margin = new Padding(4);
            groupBoxSM4Encrypt.Name = "groupBoxSM4Encrypt";
            groupBoxSM4Encrypt.Padding = new Padding(4);
            groupBoxSM4Encrypt.Size = new Size(1260, 294);
            groupBoxSM4Encrypt.TabIndex = 1;
            groupBoxSM4Encrypt.TabStop = false;
            groupBoxSM4Encrypt.Text = "SM4加密解密";
            // 
            // labelSM4CiphertextFormat
            // 
            labelSM4CiphertextFormat.AutoSize = true;
            labelSM4CiphertextFormat.Location = new Point(534, 71);
            labelSM4CiphertextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4CiphertextFormat.Name = "labelSM4CiphertextFormat";
            labelSM4CiphertextFormat.Size = new Size(73, 20);
            labelSM4CiphertextFormat.TabIndex = 9;
            labelSM4CiphertextFormat.Text = "密文格式:";
            // 
            // comboSM4CiphertextFormat
            // 
            comboSM4CiphertextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4CiphertextFormat.FormattingEnabled = true;
            comboSM4CiphertextFormat.Items.AddRange(new object[] { "Base64", "Hex" });
            comboSM4CiphertextFormat.Location = new Point(617, 67);
            comboSM4CiphertextFormat.Margin = new Padding(4);
            comboSM4CiphertextFormat.Name = "comboSM4CiphertextFormat";
            comboSM4CiphertextFormat.Size = new Size(127, 28);
            comboSM4CiphertextFormat.TabIndex = 8;
            // 
            // labelSM4PlaintextFormat
            // 
            labelSM4PlaintextFormat.AutoSize = true;
            labelSM4PlaintextFormat.Location = new Point(534, 33);
            labelSM4PlaintextFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4PlaintextFormat.Name = "labelSM4PlaintextFormat";
            labelSM4PlaintextFormat.Size = new Size(73, 20);
            labelSM4PlaintextFormat.TabIndex = 11;
            labelSM4PlaintextFormat.Text = "明文格式:";
            // 
            // comboSM4PlaintextFormat
            // 
            comboSM4PlaintextFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4PlaintextFormat.FormattingEnabled = true;
            comboSM4PlaintextFormat.Items.AddRange(new object[] { "Text", "Base64", "Hex" });
            comboSM4PlaintextFormat.Location = new Point(617, 29);
            comboSM4PlaintextFormat.Margin = new Padding(4);
            comboSM4PlaintextFormat.Name = "comboSM4PlaintextFormat";
            comboSM4PlaintextFormat.Size = new Size(127, 28);
            comboSM4PlaintextFormat.TabIndex = 10;
            // 
            // label15
            // 
            label15.AutoSize = true;
            label15.Location = new Point(276, 33);
            label15.Margin = new Padding(4, 0, 4, 0);
            label15.Name = "label15";
            label15.Size = new Size(73, 20);
            label15.TabIndex = 7;
            label15.Text = "填充模式:";
            // 
            // comboSM4Padding
            // 
            comboSM4Padding.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Padding.FormattingEnabled = true;
            comboSM4Padding.Items.AddRange(new object[] { "PKCS7", "PKCS5", "NoPadding" });
            comboSM4Padding.Location = new Point(360, 29);
            comboSM4Padding.Margin = new Padding(4);
            comboSM4Padding.Name = "comboSM4Padding";
            comboSM4Padding.Size = new Size(127, 28);
            comboSM4Padding.TabIndex = 6;
            // 
            // label14
            // 
            label14.AutoSize = true;
            label14.Location = new Point(19, 33);
            label14.Margin = new Padding(4, 0, 4, 0);
            label14.Name = "label14";
            label14.Size = new Size(73, 20);
            label14.TabIndex = 5;
            label14.Text = "加密模式:";
            // 
            // comboSM4Mode
            // 
            comboSM4Mode.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4Mode.FormattingEnabled = true;
            comboSM4Mode.Items.AddRange(new object[] { "ECB", "CBC" });
            comboSM4Mode.Location = new Point(103, 29);
            comboSM4Mode.Margin = new Padding(4);
            comboSM4Mode.Name = "comboSM4Mode";
            comboSM4Mode.Size = new Size(127, 28);
            comboSM4Mode.TabIndex = 4;
            comboSM4Mode.SelectedIndexChanged += comboSM4Mode_SelectedIndexChanged;
            // 
            // label13
            // 
            label13.AutoSize = true;
            label13.Location = new Point(19, 186);
            label13.Margin = new Padding(4, 0, 4, 0);
            label13.Name = "label13";
            label13.Size = new Size(43, 20);
            label13.TabIndex = 5;
            label13.Text = "密文:";
            // 
            // textSM4CipherText
            // 
            textSM4CipherText.Location = new Point(103, 182);
            textSM4CipherText.Margin = new Padding(4);
            textSM4CipherText.Multiline = true;
            textSM4CipherText.Name = "textSM4CipherText";
            textSM4CipherText.ScrollBars = ScrollBars.Both;
            textSM4CipherText.Size = new Size(1137, 58);
            textSM4CipherText.TabIndex = 3;
            // 
            // label12
            // 
            label12.AutoSize = true;
            label12.Location = new Point(19, 115);
            label12.Margin = new Padding(4, 0, 4, 0);
            label12.Name = "label12";
            label12.Size = new Size(43, 20);
            label12.TabIndex = 3;
            label12.Text = "明文:";
            // 
            // textSM4PlainText
            // 
            textSM4PlainText.Location = new Point(103, 112);
            textSM4PlainText.Margin = new Padding(4);
            textSM4PlainText.Multiline = true;
            textSM4PlainText.Name = "textSM4PlainText";
            textSM4PlainText.ScrollBars = ScrollBars.Both;
            textSM4PlainText.Size = new Size(1137, 58);
            textSM4PlainText.TabIndex = 2;
            // 
            // btnSM4Decrypt
            // 
            btnSM4Decrypt.Location = new Point(885, 29);
            btnSM4Decrypt.Margin = new Padding(4);
            btnSM4Decrypt.Name = "btnSM4Decrypt";
            btnSM4Decrypt.Size = new Size(103, 28);
            btnSM4Decrypt.TabIndex = 1;
            btnSM4Decrypt.Text = "解密";
            btnSM4Decrypt.UseVisualStyleBackColor = true;
            btnSM4Decrypt.Click += btnSM4Decrypt_Click;
            // 
            // btnSM4Encrypt
            // 
            btnSM4Encrypt.Location = new Point(757, 29);
            btnSM4Encrypt.Margin = new Padding(4);
            btnSM4Encrypt.Name = "btnSM4Encrypt";
            btnSM4Encrypt.Size = new Size(103, 28);
            btnSM4Encrypt.TabIndex = 0;
            btnSM4Encrypt.Text = "加密";
            btnSM4Encrypt.UseVisualStyleBackColor = true;
            btnSM4Encrypt.Click += btnSM4Encrypt_Click;
            // 
            // groupBoxSM4Keys
            // 
            groupBoxSM4Keys.Controls.Add(labelSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4IVFormat);
            groupBoxSM4Keys.Controls.Add(labelSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(comboSM4KeyFormat);
            groupBoxSM4Keys.Controls.Add(label11);
            groupBoxSM4Keys.Controls.Add(textSM4IV);
            groupBoxSM4Keys.Controls.Add(label10);
            groupBoxSM4Keys.Controls.Add(textSM4Key);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4IV);
            groupBoxSM4Keys.Controls.Add(btnGenerateSM4Key);
            groupBoxSM4Keys.Location = new Point(8, 7);
            groupBoxSM4Keys.Margin = new Padding(4);
            groupBoxSM4Keys.Name = "groupBoxSM4Keys";
            groupBoxSM4Keys.Padding = new Padding(4);
            groupBoxSM4Keys.Size = new Size(1260, 159);
            groupBoxSM4Keys.TabIndex = 0;
            groupBoxSM4Keys.TabStop = false;
            groupBoxSM4Keys.Text = "SM4密钥生成";
            // 
            // labelSM4IVFormat
            // 
            labelSM4IVFormat.AutoSize = true;
            labelSM4IVFormat.Location = new Point(752, 104);
            labelSM4IVFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4IVFormat.Name = "labelSM4IVFormat";
            labelSM4IVFormat.Size = new Size(73, 20);
            labelSM4IVFormat.TabIndex = 11;
            labelSM4IVFormat.Text = "向量格式:";
            // 
            // comboSM4IVFormat
            // 
            comboSM4IVFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4IVFormat.FormattingEnabled = true;
            comboSM4IVFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4IVFormat.Location = new Point(836, 100);
            comboSM4IVFormat.Margin = new Padding(4);
            comboSM4IVFormat.Name = "comboSM4IVFormat";
            comboSM4IVFormat.Size = new Size(102, 28);
            comboSM4IVFormat.TabIndex = 10;
            comboSM4IVFormat.SelectedIndexChanged += comboSM4IVFormat_SelectedIndexChanged;
            // 
            // labelSM4KeyFormat
            // 
            labelSM4KeyFormat.AutoSize = true;
            labelSM4KeyFormat.Location = new Point(752, 45);
            labelSM4KeyFormat.Margin = new Padding(4, 0, 4, 0);
            labelSM4KeyFormat.Name = "labelSM4KeyFormat";
            labelSM4KeyFormat.Size = new Size(73, 20);
            labelSM4KeyFormat.TabIndex = 9;
            labelSM4KeyFormat.Text = "密钥格式:";
            // 
            // comboSM4KeyFormat
            // 
            comboSM4KeyFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboSM4KeyFormat.FormattingEnabled = true;
            comboSM4KeyFormat.Items.AddRange(new object[] { "Base64", "Hex", "Text" });
            comboSM4KeyFormat.Location = new Point(836, 41);
            comboSM4KeyFormat.Margin = new Padding(4);
            comboSM4KeyFormat.Name = "comboSM4KeyFormat";
            comboSM4KeyFormat.Size = new Size(102, 28);
            comboSM4KeyFormat.TabIndex = 8;
            // 
            // label11
            // 
            label11.AutoSize = true;
            label11.Location = new Point(19, 104);
            label11.Margin = new Padding(4, 0, 4, 0);
            label11.Name = "label11";
            label11.Size = new Size(73, 20);
            label11.TabIndex = 5;
            label11.Text = "初始向量:";
            // 
            // textSM4IV
            // 
            textSM4IV.Location = new Point(103, 100);
            textSM4IV.Margin = new Padding(4);
            textSM4IV.Name = "textSM4IV";
            textSM4IV.Size = new Size(642, 27);
            textSM4IV.TabIndex = 4;
            // 
            // label10
            // 
            label10.AutoSize = true;
            label10.Location = new Point(19, 45);
            label10.Margin = new Padding(4, 0, 4, 0);
            label10.Name = "label10";
            label10.Size = new Size(76, 20);
            label10.TabIndex = 3;
            label10.Text = "SM4密钥:";
            // 
            // textSM4Key
            // 
            textSM4Key.Location = new Point(103, 41);
            textSM4Key.Margin = new Padding(4);
            textSM4Key.Name = "textSM4Key";
            textSM4Key.Size = new Size(642, 27);
            textSM4Key.TabIndex = 2;
            // 
            // btnGenerateSM4IV
            // 
            btnGenerateSM4IV.Location = new Point(967, 100);
            btnGenerateSM4IV.Margin = new Padding(4);
            btnGenerateSM4IV.Name = "btnGenerateSM4IV";
            btnGenerateSM4IV.Size = new Size(103, 28);
            btnGenerateSM4IV.TabIndex = 1;
            btnGenerateSM4IV.Text = "生成向量";
            btnGenerateSM4IV.UseVisualStyleBackColor = true;
            btnGenerateSM4IV.Click += btnGenerateSM4IV_Click;
            // 
            // btnGenerateSM4Key
            // 
            btnGenerateSM4Key.Location = new Point(967, 41);
            btnGenerateSM4Key.Margin = new Padding(4);
            btnGenerateSM4Key.Name = "btnGenerateSM4Key";
            btnGenerateSM4Key.Size = new Size(103, 28);
            btnGenerateSM4Key.TabIndex = 0;
            btnGenerateSM4Key.Text = "生成密钥";
            btnGenerateSM4Key.UseVisualStyleBackColor = true;
            btnGenerateSM4Key.Click += btnGenerateSM4Key_Click;
            // 
            // SM4TabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(groupBoxSM4Encrypt);
            Controls.Add(groupBoxSM4Keys);
            Margin = new Padding(4);
            Name = "SM4TabControl";
            Size = new Size(1278, 500);
            groupBoxSM4Encrypt.ResumeLayout(false);
            groupBoxSM4Encrypt.PerformLayout();
            groupBoxSM4Keys.ResumeLayout(false);
            groupBoxSM4Keys.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private GroupBox groupBoxSM4Encrypt;
        private Label labelSM4CiphertextFormat;
        private ComboBox comboSM4CiphertextFormat;
        private Label labelSM4PlaintextFormat;
        private ComboBox comboSM4PlaintextFormat;
        private Label label15;
        private ComboBox comboSM4Padding;
        private Label label14;
        private ComboBox comboSM4Mode;
        private Label label13;
        private TextBox textSM4CipherText;
        private Label label12;
        private TextBox textSM4PlainText;
        private Button btnSM4Decrypt;
        private Button btnSM4Encrypt;
        private GroupBox groupBoxSM4Keys;
        private Label labelSM4IVFormat;
        private ComboBox comboSM4IVFormat;
        private Label labelSM4KeyFormat;
        private ComboBox comboSM4KeyFormat;
        private Label label11;
        private TextBox textSM4IV;
        private Label label10;
        private TextBox textSM4Key;
        private Button btnGenerateSM4IV;
        private Button btnGenerateSM4Key;
    }
}