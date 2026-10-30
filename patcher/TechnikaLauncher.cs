using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class TechnikaLauncher
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            string root = AppDomain.CurrentDomain.BaseDirectory;
            string script = Path.Combine(root, "patcher", "Start-Technika.ps1");
            if (!File.Exists(script)) throw new FileNotFoundException("缺少启动补丁文件：", script);
            string options = "";
            if (args.Length != 0)
            {
                int seconds;
                if (args.Length != 2 || args[0] != "--verify-seconds" || !int.TryParse(args[1], out seconds) || seconds < 1 || seconds > 900)
                    throw new ArgumentException("支持的测试参数：--verify-seconds 1到900");
                options = " -VerifySeconds " + seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
            string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            var start = new ProcessStartInfo(powershell, "-NoProfile -ExecutionPolicy RemoteSigned -File \"" + script + "\"" + options);
            start.WorkingDirectory = root;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.WindowStyle = ProcessWindowStyle.Hidden;
            using (var helper = Process.Start(start))
            {
                helper.WaitForExit();
                return helper.ExitCode;
            }
        }
        catch (Exception error)
        {
            if (args.Length == 0) MessageBox.Show(error.Message, "TECHNIKA 启动失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
