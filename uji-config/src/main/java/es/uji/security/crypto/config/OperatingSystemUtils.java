package es.uji.security.crypto.config;

public class OperatingSystemUtils
{
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
}