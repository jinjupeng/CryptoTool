using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;
using Octokit;

namespace CryptoTool.Win
{
    /// <summary>
    /// ����������û��ؼ������������Ϣ���Զ����¹���
    /// </summary>
    public partial class AboutTabControl : UserControl
    {
        #region �¼�����

        /// <summary>
        /// ״̬�����¼�
        /// </summary>
        public event Action<string>? StatusChanged;

        #endregion

        #region ˽���ֶ�

        private GitHubClient? _gitHubClient;
        private Release? _latestRelease;
        private readonly string _repositoryOwner = "jinjupeng";
        private readonly string _repositoryName = "CryptoTool";
        private readonly HttpClient _httpClient;

        #endregion

        #region ���캯��

        public AboutTabControl()
        {
            InitializeComponent();
            _httpClient = new HttpClient();
            _gitHubClient = new GitHubClient(new ProductHeaderValue("CryptoTool"));
            InitializeAppInfo();
        }

        #endregion

        #region ��ʼ������

        /// <summary>
        /// ��ʼ�������Ϣ
        /// </summary>
        private void InitializeAppInfo()
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var version = assembly.GetName().Version?.ToString() ?? "δ֪�汾";
                var location = assembly.Location;
                var appPath = Path.GetDirectoryName(location) ?? "δ֪·��";

                // ���������Ϣ
                textAppName.Text = "CryptoTool �ӽ��ܹ���";
                textAppVersion.Text = version;
                textAppAuthor.Text = "CryptoTool";
                textAppDescription.Text = "һ������ǿ��ļӽ��ܹ��ߣ�֧��RSA��SM2��SM3��SM4�ȶ��ּӽ����㷨��" +
                                        "�Լ�ҽ���ӿڵ�ǩ����ǩ�ͼӽ��ܹ��ܡ��ṩֱ�۵�ͼ�ν��棬�����û����и��ּӽ��ܲ�����";
                linkAppRepository.Text = "CryptoTool";
                textAppLicense.Text = "MIT License";

                // ��ǰ�汾��Ϣ
                textCurrentVersion.Text = version;

                // ϵͳ��Ϣ
                textOSInfo.Text = GetOSInfo();
                textDotNetVersion.Text = Environment.Version.ToString();
                textAppPath.Text = appPath;

                // ��ʼ״̬
                textUpdateStatus.Text = "��������°�ť��ȡ���°汾��Ϣ";
                textLatestVersion.Text = "δ֪";

                SetStatus("�����Ϣ��ʼ�����");
            }
            catch (Exception ex)
            {
                SetStatus($"��ʼ�������Ϣʧ��: {ex.Message}");
            }
        }

        /// <summary>
        /// ��ȡ����ϵͳ��Ϣ
        /// </summary>
        /// <returns></returns>
        private static string GetOSInfo()
        {
            try
            {
                var osDescription = RuntimeInformation.OSDescription;
                var architecture = RuntimeInformation.OSArchitecture.ToString();
                return $"{osDescription} ({architecture})";
            }
            catch
            {
                return "δ֪����ϵͳ";
            }
        }

        #endregion

        #region �¼�������

        /// <summary>
        /// �ֿ����ӵ���¼�
        /// </summary>
        private void LinkAppRepository_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = linkAppRepository.Text,
                    UseShellExecute = true
                });
            }
            catch (Exception ex)
            {
                MessageBox.Show($"�޷�������: {ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// �����°�ť����¼�
        /// </summary>
        private async void BtnCheckUpdate_Click(object sender, EventArgs e)
        {
            btnCheckUpdate.Enabled = false;
            textUpdateStatus.Text = "���ڼ�����...";
            SetStatus("���ڼ�����...");

            try
            {
                await CheckForUpdatesAsync();
            }
            catch (Exception ex)
            {
                textUpdateStatus.Text = $"������ʧ��: {ex.Message}";
                SetStatus($"������ʧ��: {ex.Message}");
            }
            finally
            {
                btnCheckUpdate.Enabled = true;
            }
        }

        /// <summary>
        /// ���ظ��°�ť����¼�
        /// </summary>
        private async void BtnDownloadUpdate_Click(object sender, EventArgs e)
        {
            if (_latestRelease == null)
            {
                MessageBox.Show("δ��ȡ�����°汾��Ϣ", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            btnDownloadUpdate.Enabled = false;
            progressUpdate.Visible = true;
            progressUpdate.Value = 0;
            textUpdateStatus.Text = "�������ظ���...";
            SetStatus("�������ظ���...");

            try
            {
                await DownloadAndInstallUpdateAsync(_latestRelease);
            }
            catch (Exception ex)
            {
                textUpdateStatus.Text = $"���ظ���ʧ��: {ex.Message}";
                SetStatus($"���ظ���ʧ��: {ex.Message}");
                MessageBox.Show($"���ظ���ʧ��: {ex.Message}", "����", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnDownloadUpdate.Enabled = true;
                progressUpdate.Visible = false;
            }
        }

        #endregion

        #region ������ط���

        /// <summary>
        /// �첽������
        /// </summary>
        private async Task CheckForUpdatesAsync()
        {
            if (_gitHubClient == null)
            {
                throw new InvalidOperationException("GitHub�ͻ���δ��ʼ��");
            }

            try
            {
                _latestRelease = await _gitHubClient.Repository.Release.GetLatest(_repositoryOwner, _repositoryName);
                
                textLatestVersion.Text = _latestRelease.TagName;
                
                var currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
                var latestVersionString = _latestRelease.TagName.TrimStart('v');
                
                if (Version.TryParse(latestVersionString, out var latestVersion) && currentVersion != null)
                {
                    var comparison = currentVersion.CompareTo(latestVersion);
                    if (comparison < 0)
                    {
                        textUpdateStatus.Text = "�����°汾���������ظ���";
                        btnDownloadUpdate.Enabled = true;
                        SetStatus("�����°汾");
                    }
                    else if (comparison == 0)
                    {
                        textUpdateStatus.Text = "��ǰ�汾�����°汾";
                        btnDownloadUpdate.Enabled = false;
                        SetStatus("��ǰ�汾�����°汾");
                    }
                    else
                    {
                        textUpdateStatus.Text = "��ǰ�汾�����°汾���ߣ������汾��";
                        btnDownloadUpdate.Enabled = false;
                        SetStatus("��ǰ�汾�����°汾����");
                    }
                }
                else
                {
                    textUpdateStatus.Text = "�汾�Ƚ�ʧ�ܣ����ѻ�ȡ�����°汾��Ϣ";
                    btnDownloadUpdate.Enabled = true;
                    SetStatus("�汾�Ƚ�ʧ��");
                }
            }
            catch (RateLimitExceededException)
            {
                textUpdateStatus.Text = "GitHub API����������ƣ����Ժ�����";
                SetStatus("GitHub API�����������");
            }
            catch (NotFoundException)
            {
                textUpdateStatus.Text = "δ�ҵ�����ֿ��汾��Ϣ";
                SetStatus("δ�ҵ�����ֿ�");
            }
            catch (Exception ex)
            {
                textUpdateStatus.Text = $"������ʧ��: {ex.Message}";
                SetStatus($"������ʧ��: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// ��Ĭ�����£����ں�̨��⣩
        /// </summary>
        /// <returns>������°汾���� Release ���󣬷��򷵻� null</returns>
        public async Task<Release?> SilentCheckForUpdatesAsync()
        {
            if (_gitHubClient == null)
            {
                return null;
            }

            try
            {
                var latestRelease = await _gitHubClient.Repository.Release.GetLatest(_repositoryOwner, _repositoryName);
                
                var currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
                var latestVersionString = latestRelease.TagName.TrimStart('v');
                
                if (Version.TryParse(latestVersionString, out var latestVersion) && currentVersion != null)
                {
                    var comparison = currentVersion.CompareTo(latestVersion);
                    if (comparison < 0)
                    {
                        return latestRelease; // �����°汾
                    }
                }
                
                return null; // û���°汾
            }
            catch (Exception)
            {
                return null; // ���ʧ�ܣ���Ĭ����
            }
        }

        /// <summary>
        /// ��ʼ���ظ������̣����ⲿ���ã�
        /// </summary>
        /// <param name="release">Ҫ���صİ汾</param>
        public async Task StartDownloadUpdateAsync(Release release)
        {
            _latestRelease = release;
            textLatestVersion.Text = release.TagName;
            btnDownloadUpdate.Enabled = false;
            
            // �л�������ѡ�
            var parentForm = this.FindForm();
            if (parentForm is MainForm mainForm)
            {
                // �������ѡ������һ��
                var tabControl = mainForm.Controls.OfType<TabControl>().FirstOrDefault();
                if (tabControl != null)
                {
                    tabControl.SelectedIndex = tabControl.TabCount - 1; // �л�������ѡ�
                }
            }

            await DownloadAndInstallUpdateAsync(release);
        }

        /// <summary>
        /// ���ز���װ����
        /// </summary>
        private async Task DownloadAndInstallUpdateAsync(Release release)
        {
            // ����Windows��ִ���ļ���װ��
            ReleaseAsset? installerAsset = null;
            
            // ���Ȳ��ҿ�ִ���ļ�
            foreach (var asset in release.Assets)
            {
                // ����exe�ļ������ȣ�
                if (asset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && 
                    (asset.Name.Contains("win", StringComparison.OrdinalIgnoreCase) || 
                     asset.Name.Contains("windows", StringComparison.OrdinalIgnoreCase) ||
                     asset.Name.Contains("CryptoTool", StringComparison.OrdinalIgnoreCase)))
                {
                    installerAsset = asset;
                    break;
                }
            }
            
            // ���û�ҵ�exe������MSI��װ��
            if (installerAsset == null)
            {
                foreach (var asset in release.Assets)
                {
                    if (asset.Name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                    {
                        installerAsset = asset;
                        break;
                    }
                }
            }
            
            // �������û�ҵ�������ZIP��
            if (installerAsset == null)
            {
                foreach (var asset in release.Assets)
                {
                    if (asset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase) && 
                        (asset.Name.Contains("win", StringComparison.OrdinalIgnoreCase) || 
                         asset.Name.Contains("windows", StringComparison.OrdinalIgnoreCase) ||
                         asset.Name.Contains("CryptoTool", StringComparison.OrdinalIgnoreCase)))
                    {
                        installerAsset = asset;
                        break;
                    }
                }
            }

            if (installerAsset == null)
            {
                throw new InvalidOperationException("δ�ҵ�������Windows�İ�װ�����ִ���ļ�");
            }

            var tempPath = Path.GetTempPath();
            var downloadPath = Path.Combine(tempPath, installerAsset.Name);

            try
            {
                // �����ļ�
                var progress = new Progress<int>(value =>
                {
                    if (progressUpdate.InvokeRequired)
                    {
                        progressUpdate.Invoke(() =>
                        {
                            progressUpdate.Value = value;
                            textUpdateStatus.Text = $"�������ظ���... ({value}%)";
                        });
                    }
                    else
                    {
                        progressUpdate.Value = value;
                        textUpdateStatus.Text = $"�������ظ���... ({value}%)";
                    }
                    SetStatus($"�������ظ���... ({value}%)");
                });

                await DownloadFileWithProgressAsync(installerAsset.BrowserDownloadUrl, downloadPath, progress);

                textUpdateStatus.Text = "������ɣ�׼����װ...";
                SetStatus("������ɣ�׼����װ...");

                // �����ļ����ʹ���ͬ�İ�װ��ʽ
                if (installerAsset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleExecutableUpdate(downloadPath, release, installerAsset);
                }
                else if (installerAsset.Name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleMsiUpdate(downloadPath, release, installerAsset);
                }
                else if (installerAsset.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    await HandleZipUpdate(downloadPath, release, installerAsset);
                }
            }
            catch (Exception ex)
            {
                // �������ص��ļ�
                try
                {
                    if (File.Exists(downloadPath))
                    {
                        File.Delete(downloadPath);
                    }
                }
                catch { }
                
                throw new InvalidOperationException($"���ػ������ʧ��: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// �����ִ���ļ�����
        /// </summary>
        private async Task HandleExecutableUpdate(string downloadPath, Release release, ReleaseAsset asset)
        {
            var result = MessageBox.Show(
                $"���³�����������ɣ��Ƿ������滻��ǰ����\n\n�汾: {release.TagName}\n�ļ�: {asset.Name}\n\n���\"��\"���ر�Ӧ�ó��򲢸��µ��°汾��",
                "��װ����",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                try
                {
                    // ��ȡ��ǰӦ�ó���·��
                    var currentExePath = System.Windows.Forms.Application.ExecutablePath;
                    var backupPath = currentExePath + ".backup";
                    
                    // �������½ű�
                    var updateScript = Path.Combine(Path.GetTempPath(), "CryptoTool_Update.bat");
                    var scriptContent = "@echo off\r\n" +
                        "echo ���ڸ��� CryptoTool...\r\n" +
                        "timeout /t 2 /nobreak >nul\r\n" +
                        "\r\n" +
                        "echo ���ݵ�ǰ�汾...\r\n" +
                        $"if exist \"{backupPath}\" del \"{backupPath}\"\r\n" +
                        $"move \"{currentExePath}\" \"{backupPath}\"\r\n" +
                        "\r\n" +
                        "echo ��װ�°汾...\r\n" +
                        $"move \"{downloadPath}\" \"{currentExePath}\"\r\n" +
                        "\r\n" +
                        "echo �����°汾...\r\n" +
                        $"start \"\" \"{currentExePath}\"\r\n" +
                        "\r\n" +
                        "echo ������ʱ�ļ�...\r\n" +
                        "timeout /t 2 /nobreak >nul\r\n" +
                        $"if exist \"{backupPath}\" del \"{backupPath}\"\r\n" +
                        "del \"%~f0\"\r\n";
                    
                    await File.WriteAllTextAsync(updateScript, scriptContent, System.Text.Encoding.UTF8);
                    
                    // �������½ű�
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = updateScript,
                        UseShellExecute = true,
                        WindowStyle = ProcessWindowStyle.Hidden
                    });
                    
                    // �ر�Ӧ�ó���
                    System.Windows.Forms.Application.Exit();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"�Զ�����ʧ��: {ex.Message}\n\n���ֶ��滻�����ļ���\n{downloadPath}", 
                        "����ʧ��", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            else
            {
                textUpdateStatus.Text = $"���³��������ص�: {downloadPath}";
                SetStatus("���³���������ɣ��û�ѡ���Ժ��ֶ���װ");
                
                MessageBox.Show($"���³��������ص���ʱĿ¼��\n{downloadPath}\n\n���ֶ��滻��ǰ�����ļ�����ɸ��¡�", 
                    "�������", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        /// <summary>
        /// ����MSI��װ������
        /// </summary>
        private async Task HandleMsiUpdate(string downloadPath, Release release, ReleaseAsset asset)
        {
            var result = MessageBox.Show(
                $"MSI��װ����������ɣ��Ƿ�������װ��\n\n�汾: {release.TagName}\n�ļ�: {asset.Name}\n\n���\"��\"��������װ����",
                "��װ����",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (result == DialogResult.Yes)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "msiexec",
                    Arguments = $"/i \"{downloadPath}\" /quiet",
                    UseShellExecute = true
                });

                textUpdateStatus.Text = "MSI��װ����������";
                SetStatus("MSI��װ����������");
            }
            else
            {
                textUpdateStatus.Text = $"MSI��װ�������ص�: {downloadPath}";
                SetStatus("MSI��װ��������ɣ��û�ѡ���Ժ�װ");
            }
        }

        /// <summary>
        /// ����ZIPѹ��������
        /// </summary>
        private async Task HandleZipUpdate(string downloadPath, Release release, ReleaseAsset asset)
        {
            var result = MessageBox.Show(
                $"����ѹ������������ɡ�\n\n�汾: {release.TagName}\n�ļ�: {asset.Name}\n\n���ֶ���ѹ���滻�����ļ���\n\n�Ƿ�������ļ��У�",
                "�������",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Information);

            if (result == DialogResult.Yes)
            {
                // �򿪰��������ļ����ļ���
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer",
                    Arguments = $"/select,\"{downloadPath}\"",
                    UseShellExecute = true
                });
            }

            textUpdateStatus.Text = $"ZIPѹ���������ص�: {downloadPath}";
            SetStatus("ZIPѹ�����������");
        }

        /// <summary>
        /// �����ȵ��ļ�����
        /// </summary>
        private async Task DownloadFileWithProgressAsync(string url, string destinationPath, IProgress<int> progress)
        {
            using var response = await _httpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? -1L;
            var downloadedBytes = 0L;

            using var contentStream = await response.Content.ReadAsStreamAsync();
            using var fileStream = new FileStream(destinationPath, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None);

            var buffer = new byte[8192];
            var bytesRead = 0;

            while ((bytesRead = await contentStream.ReadAsync(buffer)) > 0)
            {
                await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead));
                downloadedBytes += bytesRead;

                if (totalBytes > 0)
                {
                    var percentage = (int)((downloadedBytes * 100) / totalBytes);
                    progress.Report(percentage);
                }
            }
        }

        #endregion

        #region ��������

        /// <summary>
        /// ����״̬��Ϣ
        /// </summary>
        /// <param name="message">״̬��Ϣ</param>
        private void SetStatus(string message)
        {
            StatusChanged?.Invoke(message);
        }

        #endregion
    }
}