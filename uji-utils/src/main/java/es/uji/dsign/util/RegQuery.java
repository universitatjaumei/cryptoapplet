package es.uji.dsign.util;

import java.io.InputStream;
import java.io.StringWriter;

public class RegQuery
{
	private String REGQUERY_UTIL = "reg query ";
	private String REGSTR_TOKEN = "REG_SZ";
	private String APP_DATA_CMD = REGQUERY_UTIL + "\"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\" /v APPDATA";
	private String APP_PATH_CMD = REGQUERY_UTIL + "\"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\";

	private String _execAndGetValue(String cmd)
	{
		int c;
		String res = null;
		StringWriter sw = new StringWriter();

		//System.out.println("Ejecutando y obteniendo valor ... ");
		try
		{
			InputStream in = Runtime.getRuntime().exec(cmd).getInputStream();

			
			//System.out.println("Obtenido stream: ");
			
			while ((c = in.read()) != -1)
			{
				//System.out.println("c=" + c);
				sw.write(c);
			}
			//System.out.println();
			
			in.close();
			res = sw.toString();
			//System.out.println("res: " + res );
			int p = res.indexOf(REGSTR_TOKEN);

			if (p == -1)
			{
				return null;
			}
			
			return res.substring(p + REGSTR_TOKEN.length()).trim();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Get the Application Data directory in windows.
	 * 
	 * @return A string with that path.
	 */
	public String getCurrentUserPersonalFolderPath()
	{
		//System.out.println("Ejecutando: " + APP_DATA_CMD);
		return _execAndGetValue(APP_DATA_CMD);
	}

	/**
	 * Get the Application Data directory in windows.
	 * 
	 * @param execName
	 * @return A string with that path.
	 */
	public String getAbsoluteApplicationPath(String execName)
	{
		APP_PATH_CMD += execName + "\"" + " /v Path";
		return _execAndGetValue(APP_PATH_CMD);
	}
}