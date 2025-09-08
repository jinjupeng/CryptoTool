namespace CryptoTool.Win
{
    partial class RSAConvertTabControl : UserControl
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
            groupBoxKeyInput = new GroupBox();
            tableLayoutKeyInput = new TableLayoutPanel();
            panelKeyInputControls = new Panel();
            btnImportFromFile = new Button();
            btnValidateKeyPair = new Button();
            btnGetPublicKeyFromPrivate = new Button();
            label1 = new Label();
            textInputKey = new TextBox();
            panelKeyType = new Panel();
            radioPrivateKey = new RadioButton();
            radioPublicKey = new RadioButton();
            label2 = new Label();
            groupBoxConversion = new GroupBox();
            tableLayoutConversion = new TableLayoutPanel();
            panelConversionControls = new Panel();
            label3 = new Label();
            comboInputKeyType = new ComboBox();
            label4 = new Label();
            comboInputFormat = new ComboBox();
            label5 = new Label();
            comboOutputKeyType = new ComboBox();
            label6 = new Label();
            comboOutputFormat = new ComboBox();
            btnConvert = new Button();
            btnClear = new Button();
            label7 = new Label();
            textOutputKey = new TextBox();
            groupBoxActions = new GroupBox();
            tableLayoutActions = new TableLayoutPanel();
            btnSaveToFile = new Button();
            btnCopyToClipboard = new Button();
            labelValidationResult = new Label();
            mainTableLayout.SuspendLayout();
            groupBoxKeyInput.SuspendLayout();
            tableLayoutKeyInput.SuspendLayout();
            panelKeyInputControls.SuspendLayout();
            panelKeyType.SuspendLayout();
            groupBoxConversion.SuspendLayout();
            tableLayoutConversion.SuspendLayout();
            panelConversionControls.SuspendLayout();
            groupBoxActions.SuspendLayout();
            tableLayoutActions.SuspendLayout();
            SuspendLayout();
            // 
            // mainTableLayout
            // 
            mainTableLayout.ColumnCount = 1;
            mainTableLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            mainTableLayout.Controls.Add(groupBoxKeyInput, 0, 0);
            mainTableLayout.Controls.Add(groupBoxConversion, 0, 1);
            mainTableLayout.Controls.Add(groupBoxActions, 0, 2);
            mainTableLayout.Dock = DockStyle.Fill;
            mainTableLayout.Location = new Point(0, 0);
            mainTableLayout.Margin = new Padding(4);
            mainTableLayout.Name = "mainTableLayout";
            mainTableLayout.Padding = new Padding(8);
            mainTableLayout.RowCount = 3;
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 45F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 45F));
            mainTableLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 10F));
            mainTableLayout.Size = new Size(1278, 832);
            mainTableLayout.TabIndex = 0;
            // 
            // groupBoxKeyInput
            // 
            groupBoxKeyInput.Controls.Add(tableLayoutKeyInput);
            groupBoxKeyInput.Dock = DockStyle.Fill;
            groupBoxKeyInput.Location = new Point(12, 12);
            groupBoxKeyInput.Margin = new Padding(4);
            groupBoxKeyInput.Name = "groupBoxKeyInput";
            groupBoxKeyInput.Padding = new Padding(8);
            groupBoxKeyInput.Size = new Size(1254, 358);
            groupBoxKeyInput.TabIndex = 0;
            groupBoxKeyInput.TabStop = false;
            groupBoxKeyInput.Text = "密钥输入";
            // 
            // tableLayoutKeyInput
            // 
            tableLayoutKeyInput.ColumnCount = 1;
            tableLayoutKeyInput.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutKeyInput.Controls.Add(panelKeyInputControls, 0, 0);
            tableLayoutKeyInput.Controls.Add(label1, 0, 1);
            tableLayoutKeyInput.Controls.Add(textInputKey, 0, 2);
            tableLayoutKeyInput.Controls.Add(panelKeyType, 0, 3);
            tableLayoutKeyInput.Dock = DockStyle.Fill;
            tableLayoutKeyInput.Location = new Point(8, 28);
            tableLayoutKeyInput.Name = "tableLayoutKeyInput";
            tableLayoutKeyInput.RowCount = 4;
            tableLayoutKeyInput.RowStyles.Add(new RowStyle(SizeType.Absolute, 50F));
            tableLayoutKeyInput.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutKeyInput.RowStyles.Add(new RowStyle(SizeType.Percent, 80F));
            tableLayoutKeyInput.RowStyles.Add(new RowStyle(SizeType.Percent, 20F));
            tableLayoutKeyInput.Size = new Size(1238, 322);
            tableLayoutKeyInput.TabIndex = 0;
            // 
            // panelKeyInputControls
            // 
            panelKeyInputControls.Controls.Add(btnGetPublicKeyFromPrivate);
            panelKeyInputControls.Controls.Add(btnValidateKeyPair);
            panelKeyInputControls.Controls.Add(btnImportFromFile);
            panelKeyInputControls.Dock = DockStyle.Fill;
            panelKeyInputControls.Location = new Point(3, 3);
            panelKeyInputControls.Name = "panelKeyInputControls";
            panelKeyInputControls.Size = new Size(1232, 44);
            panelKeyInputControls.TabIndex = 0;
            // 
            // btnImportFromFile
            // 
            btnImportFromFile.Location = new Point(0, 6);
            btnImportFromFile.Margin = new Padding(4);
            btnImportFromFile.Name = "btnImportFromFile";
            btnImportFromFile.Size = new Size(129, 32);
            btnImportFromFile.TabIndex = 0;
            btnImportFromFile.Text = "从文件导入";
            btnImportFromFile.UseVisualStyleBackColor = true;
            btnImportFromFile.Click += btnImportFromFile_Click;
            // 
            // btnValidateKeyPair
            // 
            btnValidateKeyPair.Location = new Point(140, 6);
            btnValidateKeyPair.Margin = new Padding(4);
            btnValidateKeyPair.Name = "btnValidateKeyPair";
            btnValidateKeyPair.Size = new Size(129, 32);
            btnValidateKeyPair.TabIndex = 1;
            btnValidateKeyPair.Text = "密钥对验证";
            btnValidateKeyPair.UseVisualStyleBackColor = true;
            btnValidateKeyPair.Click += btnValidateKeyPair_Click;
            // 
            // btnGetPublicKeyFromPrivate
            // 
            btnGetPublicKeyFromPrivate.Location = new Point(280, 6);
            btnGetPublicKeyFromPrivate.Margin = new Padding(4);
            btnGetPublicKeyFromPrivate.Name = "btnGetPublicKeyFromPrivate";
            btnGetPublicKeyFromPrivate.Size = new Size(149, 32);
            btnGetPublicKeyFromPrivate.TabIndex = 2;
            btnGetPublicKeyFromPrivate.Text = "从私钥提取公钥";
            btnGetPublicKeyFromPrivate.UseVisualStyleBackColor = true;
            btnGetPublicKeyFromPrivate.Click += btnGetPublicKeyFromPrivate_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Dock = DockStyle.Bottom;
            label1.Location = new Point(4, 55);
            label1.Margin = new Padding(4, 0, 4, 0);
            label1.Name = "label1";
            label1.Size = new Size(1230, 20);
            label1.TabIndex = 1;
            label1.Text = "密钥内容:";
            // 
            // textInputKey
            // 
            textInputKey.Dock = DockStyle.Fill;
            textInputKey.Location = new Point(4, 79);
            textInputKey.Margin = new Padding(4);
            textInputKey.Multiline = true;
            textInputKey.Name = "textInputKey";
            textInputKey.ScrollBars = ScrollBars.Both;
            textInputKey.Size = new Size(1230, 189);
            textInputKey.TabIndex = 2;
            textInputKey.TextChanged += textInputKey_TextChanged;
            // 
            // panelKeyType
            // 
            panelKeyType.Controls.Add(label2);
            panelKeyType.Controls.Add(radioPublicKey);
            panelKeyType.Controls.Add(radioPrivateKey);
            panelKeyType.Dock = DockStyle.Fill;
            panelKeyType.Location = new Point(3, 275);
            panelKeyType.Name = "panelKeyType";
            panelKeyType.Size = new Size(1232, 44);
            panelKeyType.TabIndex = 3;
            // 
            // radioPrivateKey
            // 
            radioPrivateKey.AutoSize = true;
            radioPrivateKey.Checked = true;
            radioPrivateKey.Location = new Point(74, 12);
            radioPrivateKey.Name = "radioPrivateKey";
            radioPrivateKey.Size = new Size(60, 24);
            radioPrivateKey.TabIndex = 0;
            radioPrivateKey.TabStop = true;
            radioPrivateKey.Text = "私钥";
            radioPrivateKey.UseVisualStyleBackColor = true;
            radioPrivateKey.CheckedChanged += textInputKey_TextChanged;
            // 
            // radioPublicKey
            // 
            radioPublicKey.AutoSize = true;
            radioPublicKey.Location = new Point(154, 12);
            radioPublicKey.Name = "radioPublicKey";
            radioPublicKey.Size = new Size(60, 24);
            radioPublicKey.TabIndex = 1;
            radioPublicKey.Text = "公钥";
            radioPublicKey.UseVisualStyleBackColor = true;
            radioPublicKey.CheckedChanged += textInputKey_TextChanged;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(0, 14);
            label2.Name = "label2";
            label2.Size = new Size(73, 20);
            label2.TabIndex = 2;
            label2.Text = "密钥类型:";
            // 
            // groupBoxConversion
            // 
            groupBoxConversion.Controls.Add(tableLayoutConversion);
            groupBoxConversion.Dock = DockStyle.Fill;
            groupBoxConversion.Location = new Point(12, 378);
            groupBoxConversion.Margin = new Padding(4);
            groupBoxConversion.Name = "groupBoxConversion";
            groupBoxConversion.Padding = new Padding(8);
            groupBoxConversion.Size = new Size(1254, 358);
            groupBoxConversion.TabIndex = 1;
            groupBoxConversion.TabStop = false;
            groupBoxConversion.Text = "格式转换";
            // 
            // tableLayoutConversion
            // 
            tableLayoutConversion.ColumnCount = 1;
            tableLayoutConversion.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutConversion.Controls.Add(panelConversionControls, 0, 0);
            tableLayoutConversion.Controls.Add(label7, 0, 1);
            tableLayoutConversion.Controls.Add(textOutputKey, 0, 2);
            tableLayoutConversion.Dock = DockStyle.Fill;
            tableLayoutConversion.Location = new Point(8, 28);
            tableLayoutConversion.Name = "tableLayoutConversion";
            tableLayoutConversion.RowCount = 3;
            tableLayoutConversion.RowStyles.Add(new RowStyle(SizeType.Absolute, 80F));
            tableLayoutConversion.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            tableLayoutConversion.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutConversion.Size = new Size(1238, 322);
            tableLayoutConversion.TabIndex = 0;
            // 
            // panelConversionControls
            // 
            panelConversionControls.Controls.Add(btnClear);
            panelConversionControls.Controls.Add(btnConvert);
            panelConversionControls.Controls.Add(comboOutputFormat);
            panelConversionControls.Controls.Add(label6);
            panelConversionControls.Controls.Add(comboOutputKeyType);
            panelConversionControls.Controls.Add(label5);
            panelConversionControls.Controls.Add(comboInputFormat);
            panelConversionControls.Controls.Add(label4);
            panelConversionControls.Controls.Add(comboInputKeyType);
            panelConversionControls.Controls.Add(label3);
            panelConversionControls.Dock = DockStyle.Fill;
            panelConversionControls.Location = new Point(3, 3);
            panelConversionControls.Name = "panelConversionControls";
            panelConversionControls.Size = new Size(1232, 74);
            panelConversionControls.TabIndex = 0;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(0, 8);
            label3.Name = "label3";
            label3.Size = new Size(88, 20);
            label3.TabIndex = 0;
            label3.Text = "输入密钥类型:";
            // 
            // comboInputKeyType
            // 
            comboInputKeyType.DropDownStyle = ComboBoxStyle.DropDownList;
            comboInputKeyType.FormattingEnabled = true;
            comboInputKeyType.Items.AddRange(new object[] { "PKCS1", "PKCS8" });
            comboInputKeyType.Location = new Point(95, 4);
            comboInputKeyType.Name = "comboInputKeyType";
            comboInputKeyType.Size = new Size(121, 28);
            comboInputKeyType.TabIndex = 1;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(235, 8);
            label4.Name = "label4";
            label4.Size = new Size(88, 20);
            label4.TabIndex = 2;
            label4.Text = "输入密钥格式:";
            // 
            // comboInputFormat
            // 
            comboInputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboInputFormat.FormattingEnabled = true;
            comboInputFormat.Items.AddRange(new object[] { "PEM", "Base64", "Hex" });
            comboInputFormat.Location = new Point(330, 4);
            comboInputFormat.Name = "comboInputFormat";
            comboInputFormat.Size = new Size(121, 28);
            comboInputFormat.TabIndex = 3;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(0, 45);
            label5.Name = "label5";
            label5.Size = new Size(88, 20);
            label5.TabIndex = 4;
            label5.Text = "输出密钥类型:";
            // 
            // comboOutputKeyType
            // 
            comboOutputKeyType.DropDownStyle = ComboBoxStyle.DropDownList;
            comboOutputKeyType.FormattingEnabled = true;
            comboOutputKeyType.Items.AddRange(new object[] { "PKCS1", "PKCS8" });
            comboOutputKeyType.Location = new Point(95, 41);
            comboOutputKeyType.Name = "comboOutputKeyType";
            comboOutputKeyType.Size = new Size(121, 28);
            comboOutputKeyType.TabIndex = 5;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(235, 45);
            label6.Name = "label6";
            label6.Size = new Size(88, 20);
            label6.TabIndex = 6;
            label6.Text = "输出密钥格式:";
            // 
            // comboOutputFormat
            // 
            comboOutputFormat.DropDownStyle = ComboBoxStyle.DropDownList;
            comboOutputFormat.FormattingEnabled = true;
            comboOutputFormat.Items.AddRange(new object[] { "PEM", "Base64", "Hex" });
            comboOutputFormat.Location = new Point(330, 41);
            comboOutputFormat.Name = "comboOutputFormat";
            comboOutputFormat.Size = new Size(121, 28);
            comboOutputFormat.TabIndex = 7;
            // 
            // btnConvert
            // 
            btnConvert.Location = new Point(470, 15);
            btnConvert.Name = "btnConvert";
            btnConvert.Size = new Size(94, 45);
            btnConvert.TabIndex = 8;
            btnConvert.Text = "转换";
            btnConvert.UseVisualStyleBackColor = true;
            btnConvert.Click += btnConvert_Click;
            // 
            // btnClear
            // 
            btnClear.Location = new Point(580, 15);
            btnClear.Name = "btnClear";
            btnClear.Size = new Size(94, 45);
            btnClear.TabIndex = 9;
            btnClear.Text = "清空";
            btnClear.UseVisualStyleBackColor = true;
            btnClear.Click += btnClear_Click;
            // 
            // label7
            // 
            label7.AutoSize = true;
            label7.Dock = DockStyle.Bottom;
            label7.Location = new Point(4, 85);
            label7.Margin = new Padding(4, 0, 4, 0);
            label7.Name = "label7";
            label7.Size = new Size(1230, 20);
            label7.TabIndex = 1;
            label7.Text = "转换结果:";
            // 
            // textOutputKey
            // 
            textOutputKey.Dock = DockStyle.Fill;
            textOutputKey.Location = new Point(4, 109);
            textOutputKey.Margin = new Padding(4);
            textOutputKey.Multiline = true;
            textOutputKey.Name = "textOutputKey";
            textOutputKey.ReadOnly = true;
            textOutputKey.ScrollBars = ScrollBars.Both;
            textOutputKey.Size = new Size(1230, 209);
            textOutputKey.TabIndex = 2;
            // 
            // groupBoxActions
            // 
            groupBoxActions.Controls.Add(tableLayoutActions);
            groupBoxActions.Dock = DockStyle.Fill;
            groupBoxActions.Location = new Point(12, 744);
            groupBoxActions.Margin = new Padding(4);
            groupBoxActions.Name = "groupBoxActions";
            groupBoxActions.Padding = new Padding(8);
            groupBoxActions.Size = new Size(1254, 76);
            groupBoxActions.TabIndex = 2;
            groupBoxActions.TabStop = false;
            groupBoxActions.Text = "操作";
            // 
            // tableLayoutActions
            // 
            tableLayoutActions.ColumnCount = 3;
            tableLayoutActions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150F));
            tableLayoutActions.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150F));
            tableLayoutActions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            tableLayoutActions.Controls.Add(btnSaveToFile, 0, 0);
            tableLayoutActions.Controls.Add(btnCopyToClipboard, 1, 0);
            tableLayoutActions.Controls.Add(labelValidationResult, 2, 0);
            tableLayoutActions.Dock = DockStyle.Fill;
            tableLayoutActions.Location = new Point(8, 28);
            tableLayoutActions.Name = "tableLayoutActions";
            tableLayoutActions.RowCount = 1;
            tableLayoutActions.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            tableLayoutActions.Size = new Size(1238, 40);
            tableLayoutActions.TabIndex = 0;
            // 
            // btnSaveToFile
            // 
            btnSaveToFile.Dock = DockStyle.Fill;
            btnSaveToFile.Location = new Point(3, 3);
            btnSaveToFile.Name = "btnSaveToFile";
            btnSaveToFile.Size = new Size(144, 34);
            btnSaveToFile.TabIndex = 0;
            btnSaveToFile.Text = "保存到文件";
            btnSaveToFile.UseVisualStyleBackColor = true;
            btnSaveToFile.Click += btnSaveToFile_Click;
            // 
            // btnCopyToClipboard
            // 
            btnCopyToClipboard.Dock = DockStyle.Fill;
            btnCopyToClipboard.Location = new Point(153, 3);
            btnCopyToClipboard.Name = "btnCopyToClipboard";
            btnCopyToClipboard.Size = new Size(144, 34);
            btnCopyToClipboard.TabIndex = 1;
            btnCopyToClipboard.Text = "复制到剪贴板";
            btnCopyToClipboard.UseVisualStyleBackColor = true;
            btnCopyToClipboard.Click += btnCopyToClipboard_Click;
            // 
            // labelValidationResult
            // 
            labelValidationResult.AutoSize = true;
            labelValidationResult.Dock = DockStyle.Fill;
            labelValidationResult.Location = new Point(303, 0);
            labelValidationResult.Name = "labelValidationResult";
            labelValidationResult.Size = new Size(932, 40);
            labelValidationResult.TabIndex = 2;
            labelValidationResult.Text = "验证结果: ";
            labelValidationResult.TextAlign = ContentAlignment.MiddleLeft;
            // 
            // RSAConvertTabControl
            // 
            AutoScaleDimensions = new SizeF(9F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(mainTableLayout);
            Margin = new Padding(4);
            Name = "RSAConvertTabControl";
            Size = new Size(1278, 832);
            mainTableLayout.ResumeLayout(false);
            groupBoxKeyInput.ResumeLayout(false);
            tableLayoutKeyInput.ResumeLayout(false);
            tableLayoutKeyInput.PerformLayout();
            panelKeyInputControls.ResumeLayout(false);
            panelKeyType.ResumeLayout(false);
            panelKeyType.PerformLayout();
            groupBoxConversion.ResumeLayout(false);
            tableLayoutConversion.ResumeLayout(false);
            tableLayoutConversion.PerformLayout();
            panelConversionControls.ResumeLayout(false);
            panelConversionControls.PerformLayout();
            groupBoxActions.ResumeLayout(false);
            tableLayoutActions.ResumeLayout(false);
            tableLayoutActions.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private TableLayoutPanel mainTableLayout;
        private GroupBox groupBoxKeyInput;
        private TableLayoutPanel tableLayoutKeyInput;
        private Panel panelKeyInputControls;
        private Button btnImportFromFile;
        private Button btnValidateKeyPair;
        private Button btnGetPublicKeyFromPrivate;
        private Label label1;
        private TextBox textInputKey;
        private Panel panelKeyType;
        private RadioButton radioPrivateKey;
        private RadioButton radioPublicKey;
        private Label label2;
        private GroupBox groupBoxConversion;
        private TableLayoutPanel tableLayoutConversion;
        private Panel panelConversionControls;
        private Label label3;
        private ComboBox comboInputKeyType;
        private Label label4;
        private ComboBox comboInputFormat;
        private Label label5;
        private ComboBox comboOutputKeyType;
        private Label label6;
        private ComboBox comboOutputFormat;
        private Button btnConvert;
        private Button btnClear;
        private Label label7;
        private TextBox textOutputKey;
        private GroupBox groupBoxActions;
        private TableLayoutPanel tableLayoutActions;
        private Button btnSaveToFile;
        private Button btnCopyToClipboard;
        private Label labelValidationResult;
    }
}