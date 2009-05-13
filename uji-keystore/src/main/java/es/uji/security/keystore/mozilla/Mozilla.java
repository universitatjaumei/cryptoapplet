package es.uji.security.keystore.mozilla;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;

import java.util.Enumeration;
import java.util.Properties;
import java.util.Random;
import java.util.Vector;

import es.uji.security.util.OS;
import es.uji.security.util.RegQuery;

/**
 * 
 * This class represents Mozilla properties and defines methods to get where it is installed, the
 * profiles that have been defined and the profile user is using now.
 * 
 * @author PSN
 */

public class Mozilla
{
    private String _userHome;
    private String[] _profileDir;
    private String _userAppDataDir;
    private String _lockFile, _execName;
    boolean _linux = false, _windows = false, _mac = false;

    /**
     * Base constructor.
     */
    public Mozilla()
    {
        _userHome = System.getProperty("user.home");

        if (OS.isLinux())
        {
            _profileDir = new String[1];
            _profileDir[0] = _userHome + "/.mozilla/firefox/";
            _lockFile = ".parentlock";
            _linux = true;
            _execName = "firefox";
        }
        else if (OS.isWindowsUpperEqualToNT())
        {
            RegQuery rq = new RegQuery();

            _userAppDataDir = rq.getCurrentUserPersonalFolderPath();
            _profileDir = new String[1];
            _profileDir[0] = _userAppDataDir + "\\Mozilla\\Firefox\\Profiles\\";
            _lockFile = "parent.lock";
            _windows = true;
            _execName = "firefox.exe";
        }
        else if (OS.isMac())
        {
            _profileDir = new String[2];
            _profileDir[0] = _userHome + "/.mozilla/firefox/";
            _profileDir[1] = _userHome + "/Library/Application Support/Firefox/Profiles/";
            _lockFile = ".parentlock";
            _mac = true;
            _execName = "firefox";
        }
    }

    /**
     * Get the current user profile being used.
     * 
     * @return An string with the path or "" if none used.
     */
    public String getCurrentProfiledir()
    {
        String res = null, aux = "";
        File dir;
        Vector<String> profiles = getProfiledirs();

        for (Enumeration<String> e = profiles.elements(); e.hasMoreElements();)
        {
            aux = e.nextElement();
            dir = new File(aux + File.separator + _lockFile);
            if (dir.exists())
            {
                res = aux + File.separator;
            }
        }
        return res;
    }

    /**
     * Get All profile dirs that user has
     * 
     * 
     * @return A Vector with absolute paths to the profiles.
     */
    public Vector<String> getProfiledirs()
    {
        Vector<String> profiles = new Vector<String>();

        for (int i = 0; i < _profileDir.length; i++)
        {
            File dir = new File(_profileDir[i]);
            String aux[] = dir.list();

            if (aux != null)
            {
                for (int j = 0; j < aux.length; j++)
                {
                    dir = new File(_profileDir[i] + aux[j]);
                    if (dir.isDirectory())
                    {
                        profiles.add(_profileDir[i] + aux[j]);
                    }
                }
            }
        }

        return profiles;
    }

    /**
     * Get installed application path for Mozilla Firefox.
     * 
     * 
     * @return A Stng with the absolute path.
     */
    public String getAbsoluteApplicationPath()
    {
        String res = null;

        if (_windows)
        {
            RegQuery r = new RegQuery();
            res = r.getAbsoluteApplicationPath(_execName);
            if (res != null)
            {
                return res;
            }
            String progFiles = System.getenv("ProgramFiles");
            String dirs[] = { "\\Mozilla\\ Firefox\\", "\\Mozilla", "\\Firefox", "\\SeaMonkey",
                    "\\mozilla.org\\SeaMonkey" };

            for (int i = 0; i < dirs.length; i++)
            {
                File f = new File(progFiles + dirs[i]);
                if (f.exists())
                {
                    return progFiles + dirs[i];
                }
            }
        }

        else if (_linux)
        {
            try
            {
                File f;
                Properties env = new Properties();
                env.load(Runtime.getRuntime().exec("env").getInputStream());
                String userPath = (String) env.get("PATH");
                String[] pathDirs = userPath.split(":");

                for (int i = 0; i < pathDirs.length; i++)
                {
                    f = new File(pathDirs[i] + File.separator + _execName);

                    if (f.exists())
                    {
                        return f.getCanonicalPath().substring(0,
                                f.getCanonicalPath().length() - _execName.length());
                    }
                }
            }
            catch (Exception e)
            {
                return null;
            }
        }

        return res;
    }

    public String getPkcs11FilePath()
    {
        if (_windows)
        {
            return getAbsoluteApplicationPath() + "\\softokn3.dll";
        }
        else if (_linux)
        {
            String dirs[] = { "/usr/lib/nss/libsoftokn3.so",
                    getAbsoluteApplicationPath() + "libsoftokn3.so", "/usr/lib/libsoftokn3.so",
                    "/lib/libsoftokn3.so", "/usr/lib/iceweasel/libsoftokn3.so",
                    "/usr/lib/mozilla//libsoftokn3.so", "/usr/lib/firefox/libsoftokn3.so",
                    "/usr/lib/iceape/libsoftokn3.so", "/usr/lib/seamonkey/libsoftokn3.so" };

            for (int i = 0; i < dirs.length; i++)
            {
                File f = new File(dirs[i]);
                if (f.exists())
                {
                    String res;
                    try
                    {
                        res = new File(dirs[i]).getCanonicalPath();
                    }
                    catch (IOException e)
                    {
                        e.printStackTrace();
                        res = null;
                    }
                    return res;
                }
            }
        }
        else if (_mac)
        {
            String res = null;
            try
            {
                File f = new File("/Applications/Firefox.app/Contents/MacOS/libsoftokn3.dylib");
                if (f.exists())
                {
                    res = f.getCanonicalPath();
                }
            }
            catch (IOException e)
            {
                res = null;
                e.printStackTrace();
            }
            return res;

        }

        return null;
    }

    public ByteArrayInputStream getPkcs11ConfigInputStream()
    {

        OS os = new OS();
        String _pkcs11file = getPkcs11FilePath();
        String _currentprofile = getCurrentProfiledir();
        ByteArrayInputStream bais = null;

        if (OS.isWindowsUpperEqualToNT())
        {
            bais = new ByteArrayInputStream(("name = NSS\r" + "library = " + _pkcs11file + "\r"
                    + "attributes= compatibility" + "\r" + "slot=2\r" + "nssArgs=\""
                    + "configdir='" + _currentprofile.replace("\\", "/") + "' " + "certPrefix='' "
                    + "keyPrefix='' " + "secmod=' secmod.db' " + "flags=readOnly\"\r").getBytes());
        }
        else if (OS.isLinux() || OS.isMac())
        {
            /*
             * TODO:With Linux is pending to test what's up with the white spaces in the path.
             */

            bais = new ByteArrayInputStream(("name = NSS\r" + "library = " + _pkcs11file + "\n"
                    + "attributes= compatibility" + "\n" + "slot=2\n" + "nssArgs=\""
                    + "configdir='" + _currentprofile + "' " + "certPrefix='' " + "keyPrefix='' "
                    + "secmod=' secmod.db' " + "flags=readOnly\"\n").getBytes());
        }

        return bais;
    }

    public String getPkcs11InitArgsString()
    {
        return "configdir='" + getCurrentProfiledir().replace("\\", "/")
                + "' certPrefix='' keyPrefix='' secmod='secmod.db' flags=";
    }
    
    public boolean isInitialized()
    {
        try
        {
            MozillaKeyStore mks = new MozillaKeyStore();
            mks.load("".toCharArray());
            mks.cleanUp();
            return true;
        }
        catch (Exception e)
        {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PrintStream ps = new PrintStream(os);
            e.printStackTrace(ps);
            String stk = new String(os.toByteArray());
            
            if (stk.indexOf("CKR_USER_TYPE_INVALID") > -1)
            {
                return false;
            }
            
            return true;
        }
    }    
}
