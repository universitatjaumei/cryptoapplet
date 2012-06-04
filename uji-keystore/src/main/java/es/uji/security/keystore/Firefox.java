package es.uji.security.keystore;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import es.uji.security.crypto.OperatingSystemUtils;

public class Firefox
{
    private List<String> guessProfileDirectories;
    private String lockFile;

    public Firefox()
    {
        String userHome = System.getProperty("user.home");

        retrieveConfigIfLinux(userHome);
        retrieveConfigIfWindows(userHome);
        retrieveConfigIfMacOSX(userHome);
    }

    private void retrieveConfigIfMacOSX(String userHome)
    {
        if (OperatingSystemUtils.isMac())
        {
            guessProfileDirectories = new ArrayList<String>();
            guessProfileDirectories.add(userHome + "/.mozilla/firefox/");
            guessProfileDirectories
                    .add(userHome + "/Library/Application Support/Firefox/Profiles/");
            lockFile = ".parentlock";
        }
    }

    private void retrieveConfigIfWindows(String userHome)
    {
        if (OperatingSystemUtils.isWindowsUpperEqualToNT())
        {
            guessProfileDirectories = Collections.singletonList(OperatingSystemUtils
                    .getCurrentUserApplicationDataDirectory() + "\\Mozilla\\Firefox\\Profiles\\");
            lockFile = "parent.lock";
        }
    }

    private void retrieveConfigIfLinux(String userHome)
    {
        if (OperatingSystemUtils.isLinux())
        {
            guessProfileDirectories = Collections.singletonList(userHome + "/.mozilla/firefox/");
            lockFile = ".parentlock";
        }
    }

    public String getCurrentProfileDirectory()
    {
        for (String baseDirectory : guessProfileDirectories)
        {
            for (String potentialProfileDirectory : new File(baseDirectory).list())
            {
                File currentDescriptor = new File(baseDirectory + potentialProfileDirectory);

                if (currentDescriptor.isDirectory())
                {
                    String[] pathsWithLockFile = currentDescriptor.list(new FilenameFilter()
                    {
                        @Override
                        public boolean accept(File dir, String name)
                        {
                            return name.equals(lockFile);
                        }
                    });

                    if (pathsWithLockFile != null && pathsWithLockFile.length > 0)
                    {
                        return potentialProfileDirectory;
                    }
                }
            }
        }

        return null;
    }

    public String getPKCS11Library()
    {
        List<String> guessPaths = new ArrayList<String>();
        guessPaths.add("/usr/lib/");
        guessPaths.add("/usr/lib/nss/");
        guessPaths.addAll(getLibraryPaths("/usr/lib/", "*-linux-gnu", "/nss/"));
        guessPaths.addAll(getLibraryPaths("/usr/lib/", "firefox-*", "/"));

        return getFirstExistingLibsoftokn3(guessPaths);
    }

    private String getFirstExistingLibsoftokn3(List<String> guessPaths)
    {
        for (String path : guessPaths)
        {
            if (libsoftokn3ExistsInPath(path))
            {
                return path;
            }
        }

        return null;
    }

    private boolean libsoftokn3ExistsInPath(String path)
    {
        File basePath = new File(path);
        String[] fileList = basePath.list(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                return name.equals("libsoftokn3.so");
            }
        });

        return (fileList != null && fileList.length > 0);
    }

    private List<String> getLibraryPaths(String basePath, final String expression, String subPath)
    {
        String[] firefoxPaths = new File(basePath).list(new FilenameFilter()
        {
            @Override
            public boolean accept(File dir, String name)
            {
                if (expression.startsWith("*"))
                {
                    return name.endsWith(expression.substring(1));
                }
                else if (expression.endsWith("*"))
                {
                    return name.startsWith(expression.substring(0, expression.length() - 2));
                }
                else
                {
                    return name.equals(expression);
                }
            }
        });

        List<String> paths = new ArrayList<String>();

        for (String path : firefoxPaths)
        {
            paths.add("/usr/lib/" + path + subPath);
        }

        return paths;
    }

    public byte[] getPKCS11Configuration()
    {
        StringBuilder config = new StringBuilder();

        config.append("name=NSS").append("\n");
        config.append("library=").append(getPKCS11Library()).append("\n");
        config.append("attributes=compatibility").append("\n");
        config.append("slot=2").append("\n");
        config.append("nssArgs=\"configdir='").append(getCurrentProfileDirectory()).append("' ");
        config.append("certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly\"");
        config.append("\n");

        return config.toString().getBytes();
    }
}