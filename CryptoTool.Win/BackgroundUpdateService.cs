using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Octokit;

namespace CryptoTool.Win
{
    /// <summary>
    /// ��̨�汾������
    /// </summary>
    public class BackgroundUpdateService
    {
        #region �¼�����

        /// <summary>
        /// �����°汾�¼�
        /// </summary>
        public event Action<Release>? NewVersionFound;

        /// <summary>
        /// ���״̬�����¼�
        /// </summary>
        public event Action<string>? StatusUpdated;

        #endregion

        #region ˽���ֶ�

        private readonly GitHubClient _gitHubClient;
        private readonly string _repositoryOwner = "jinjupeng";
        private readonly string _repositoryName = "CryptoTool";
        private readonly System.Threading.Timer _timer;
        private readonly SemaphoreSlim _semaphore;
        private bool _disposed = false;

        #endregion

        #region ���캯��

        public BackgroundUpdateService()
        {
            _gitHubClient = new GitHubClient(new ProductHeaderValue("CryptoTool"));
            _semaphore = new SemaphoreSlim(1, 1);
            
            // ������ʱ����������������
            _timer = new System.Threading.Timer(async _ => await CheckForUpdatesAsync(), null, Timeout.Infinite, Timeout.Infinite);
        }

        #endregion

        #region ��������

        /// <summary>
        /// ������̨������
        /// </summary>
        /// <param name="initialDelay">��ʼ�ӳ�ʱ�䣨���룩��Ĭ��5��</param>
        /// <param name="interval">�����ʱ�䣨���룩��Ĭ��2Сʱ</param>
        public void Start(int initialDelay = 5000, int interval = 7200000) // Ĭ��2Сʱ���һ��
        {
            if (_disposed) return;

            StatusUpdated?.Invoke("��̨���¼�����������");
            _timer.Change(initialDelay, interval);
        }

        /// <summary>
        /// ֹͣ��̨������
        /// </summary>
        public void Stop()
        {
            if (_disposed) return;

            _timer.Change(Timeout.Infinite, Timeout.Infinite);
            StatusUpdated?.Invoke("��̨���¼�������ֹͣ");
        }

        /// <summary>
        /// �ֶ������汾���
        /// </summary>
        /// <returns></returns>
        public async Task ManualCheckAsync()
        {
            if (_disposed) return;

            await CheckForUpdatesAsync();
        }

        #endregion

        #region ˽�з���

        /// <summary>
        /// �첽������
        /// </summary>
        private async Task CheckForUpdatesAsync()
        {
            if (_disposed || !await _semaphore.WaitAsync(100))
                return;

            try
            {
                StatusUpdated?.Invoke("���ں�̨������...");

                var latestRelease = await _gitHubClient.Repository.Release.GetLatest(_repositoryOwner, _repositoryName);
                
                var currentVersion = Assembly.GetExecutingAssembly().GetName().Version;
                var latestVersionString = latestRelease.TagName.TrimStart('v');
                
                if (Version.TryParse(latestVersionString, out var latestVersion) && currentVersion != null)
                {
                    var comparison = currentVersion.CompareTo(latestVersion);
                    if (comparison < 0)
                    {
                        // �����°汾
                        StatusUpdated?.Invoke($"�����°汾 {latestVersion}");
                        NewVersionFound?.Invoke(latestRelease);
                        return;
                    }
                    else if (comparison == 0)
                    {
                        StatusUpdated?.Invoke("��ǰ�汾�����°汾");
                    }
                    else
                    {
                        StatusUpdated?.Invoke("��ǰ�汾�������·����汾");
                    }
                }
                else
                {
                    StatusUpdated?.Invoke("�汾�Ƚ�ʧ��");
                }
            }
            catch (RateLimitExceededException)
            {
                StatusUpdated?.Invoke("GitHub API �������ƣ����Ժ�����");
            }
            catch (NotFoundException)
            {
                StatusUpdated?.Invoke("δ�ҵ�����ֿ�");
            }
            catch (Exception ex)
            {
                StatusUpdated?.Invoke($"��̨������ʧ��: {ex.Message}");
            }
            finally
            {
                _semaphore.Release();
            }
        }

        #endregion

        #region IDisposable ʵ��

        public void Dispose()
        {
            if (_disposed) return;

            _disposed = true;
            _timer?.Dispose();
            _semaphore?.Dispose();
            
            StatusUpdated?.Invoke("��̨���¼��������ͷ�");
        }

        #endregion
    }
}