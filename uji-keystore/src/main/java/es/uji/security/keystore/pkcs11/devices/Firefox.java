package es.uji.security.keystore.pkcs11.devices;

import java.io.File;
import java.io.FilenameFilter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import es.uji.security.crypto.OperatingSystemUtils;
import es.uji.security.keystore.pkcs11.PKCS11Configurable;
import es.uji.security.keystore.pkcs11.PKCS11Device;

public class Firefox extends PKCS11Device implements PKCS11Configurable
{
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
                        return baseDirectory + potentialProfileDirectory;
                    }
                }
            }
        }

        return null;
    }

    @Override
    public String getPKCS11Library()
    {
        List<String> guessPaths = new ArrayList<String>();
        guessPaths.add("/usr/lib/");
        guessPaths.add("/usr/lib/nss/");
        guessPaths.addAll(getLibraryPaths("/usr/lib/", "*-linux-gnu", "/nss/"));
        guessPaths.addAll(getLibraryPaths("/usr/lib/", "firefox-*", "/"));

        return getFirstExistingFileName(guessPaths, "libsoftokn3.so");
    }

    @Override
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