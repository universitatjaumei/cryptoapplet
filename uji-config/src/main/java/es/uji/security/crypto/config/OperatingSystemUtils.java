package es.uji.security.crypto.config;

import java.io.InputStream;

public class OperatingSystemUtils
{
    private final static String REGSTR_TOKEN = "REG_SZ";
    private final static String APP_DATA_REGISTRY_KEY = "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\" /v APPDATA";
    private final static String APP_PATH_REGISTRY_KEY = "\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\";

    public static String getSystemTmpDir()
    {
        return System.getProperty("java.io.tmpdir");
    }

    public static String getOS()
    {
        return System.getProperty("os.name").toLowerCase();
    }

    public static boolean isWindowsXP()
    {
        return (getOS().indexOf("windows xp") > -1);
    }

    public static boolean isWindows2000()
    {
        return (getOS().indexOf("windows 2000") > -1);
    }

    public static boolean isWindows2003()
    {
        return (getOS().indexOf("windows 2003") > -1);
    }

    public static boolean isWindowsVista()
    {
        return (getOS().indexOf("vista") > -1);
    }

    public static boolean isWindows7()
    {
        return (getOS().indexOf("windows 7") > -1);
    }

    public static boolean isWindowsNT()
    {
        return (getOS().indexOf("nt") > -1);
    }

    public static boolean isMac()
    {
        return (getOS().indexOf("mac") > -1);
    }

    public static boolean isLinux()
    {
        return (getOS().indexOf("linux") > -1);
    }

    public static boolean isWindowsUpperEqualToNT()
    {
        return (isWindowsNT() || isWindows2000() || isWindowsXP() || isWindows2003()
                || isWindowsVista() || isWindows7());
    }

    private static String executeWindowsRegistrySearch(String cmd)
    {
        try
        {
            InputStream commandOutput = Runtime.getRuntime().exec("reg query " + cmd)
                    .getInputStream();
            String result = new String(StreamUtils.inputStreamToByteArray(commandOutput));

            if (result.contains(REGSTR_TOKEN))
            {
                return result.substring(result.indexOf(REGSTR_TOKEN) + REGSTR_TOKEN.length())
                        .trim();
            }
        }
        catch (Exception e)
        {
        }

        return null;
    }

    public static String getCurrentUserApplicationDataDirectory()
    {
        return executeWindowsRegistrySearch(APP_DATA_REGISTRY_KEY);
    }

    public static String getAbsoluteApplicationDataDirectory(String execName)
    {
        String command = APP_PATH_REGISTRY_KEY + execName + "\"" + " /v Path";
        return executeWindowsRegistrySearch(command);
    }
}