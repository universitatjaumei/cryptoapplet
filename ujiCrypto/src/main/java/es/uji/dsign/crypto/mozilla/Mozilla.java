package es.uji.dsign.crypto.mozilla;

import java.io.File;
import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

import es.uji.dsign.util.OS;
import es.uji.dsign.util.RegQuery;

/**
 * 
 * This class represents Mozilla properties and defines methods to get where it
 * is installed, the profiles that have been defined and the profile user is
 * using now.
 * 
 * @author PSN
 */

public class Mozilla
{
	private String _userHome;
	private String _profileDir, _userAppDataDir;
	private String _lockFile, _execName;
	boolean _linux = false, _windows = false;

	/**
	 * Base constructor.
	 */	
	public Mozilla()
	{
		_userHome = System.getProperty("user.home");

		if (OS.isLinux())
		{
			_profileDir = _userHome + "/.mozilla/firefox/";
			_lockFile = ".parentlock";
			_linux = true;
			_execName = "firefox";
		}
		else if (OS.isWindowsUpperEqualToNT())
		{
			RegQuery rq = new RegQuery();

			_userAppDataDir = rq.getCurrentUserPersonalFolderPath();
			_profileDir = _userAppDataDir + "\\Mozilla\\Firefox\\Profiles\\";
			_lockFile = "parent.lock";
			_windows = true;
			_execName = "firefox.exe";
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
		File dir = new File(_profileDir);
		String aux[] = dir.list();
		Vector<String> profiles = new Vector<String>();

		if (aux != null)
		{
			for (int i=0; i<aux.length; i++)
			{
				dir = new File(_profileDir + aux[i]);
				if (dir.isDirectory())
				{
					profiles.add(_profileDir + aux[i]);
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
			if ( res!= null){
				return res;			
			}
			String progFiles= System.getenv("ProgramFiles"); 
			String dirs[] = {"\\Mozilla\\ Firefox\\","\\Mozilla","\\Firefox","\\SeaMonkey","\\mozilla.org\\SeaMonkey"};

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
						return f.getCanonicalPath().substring(0, f.getCanonicalPath().length() - _execName.length());
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
			String dirs[] = { "/usr/lib/nss/libsoftokn3.so", getAbsoluteApplicationPath() + "libsoftokn3.so", "/usr/lib/libsoftokn3.so",
							  "/lib/libsoftokn3.so","/usr/lib/iceweasel/libsoftokn3.so","/usr/lib/mozilla//libsoftokn3.so", 
							  "/usr/lib/firefox/libsoftokn3.so","/usr/lib/iceape/libsoftokn3.so",
							  "/usr/lib/seamonkey/libsoftokn3.so"};

			for (int i = 0; i < dirs.length; i++)
			{
				File f = new File(dirs[i]);
				if (f.exists())
				{
					String res;
					try {
						res = new File(dirs[i]).getCanonicalPath();
						System.out.println("res: " + res);
					} catch (IOException e) {
						
						e.printStackTrace();
						res=null;
					}
					return res;
				}
			}
		}
		
		return null;
	}
	
	
	public ByteArrayInputStream getPkcs11ConfigInputStream(){
		
		OS os= new OS();
		String _pkcs11file= getPkcs11FilePath();
		String _currentprofile= getCurrentProfiledir(); 
		ByteArrayInputStream bais= null; 
		
		if (OS.isWindowsUpperEqualToNT())
		{
			bais= new ByteArrayInputStream(("name = NSS\r" + 
					   "library = " + _pkcs11file + "\r" + 
					   "attributes= compatibility" + "\r" +
					   "slot=2\r" + 
					   "nssArgs=\"" + 
					   "configdir='" + _currentprofile.replace("\\", "/").replace(" ", "\\ ") + "' " +
					   "certPrefix='' " + 
					   "keyPrefix='' " + 
					   "secmod=' secmod.db' " + 
					   "flags=readOnly\"\r").getBytes());
		}
		else if (OS.isLinux())
		{
			/*
			 * TODO:With Linux is pending to test what's up with the white
			 * spaces in the path.
			 */
			
			bais= new ByteArrayInputStream(("name = NSS\n" + 
					   "library = " + _pkcs11file + "\n" + 
					   "attributes= compatibility" + "\n" +
					   "slot=2\n" + 
					   "nssArgs=\"" + 
					   "configdir='" + _currentprofile + "' " + 
					   "certPrefix='' " + 
					   "keyPrefix='' " +
					   "secmod=' secmod.db' " + 
					   "flags=readOnly\"\n").getBytes());
		}
	
		return bais;
	}
	
	public String getPkcs11InitArgsString(){
		return  "configdir='" 
				+ getCurrentProfiledir() 
				+ "' certPrefix='' keyPrefix='' secmod=' secmod.db' flags=";
	}
}
