package es.uji.dsign.util.i18n;

import java.util.Enumeration;
import java.util.Properties;
import java.util.ResourceBundle;

//import org.apache.log4j.Logger;

public class LabelManager
{
    //private Logger log = Logger.getLogger(LabelManager.class);
	
	private static LabelManager i18n;
	private Properties _prop = new Properties();
	private static String _lang=null;

	
	public static void setLang(String lang)
	{
		_lang= lang;
		if (i18n == null)
		{
			i18n = new LabelManager();
		}
	}
	
	private LabelManager()
	{
		try
		{
			ResourceBundle bundle;
			
			if ( _lang != null )
				bundle = ResourceBundle.getBundle("i18n"+ "_" + _lang);
			else
				bundle = ResourceBundle.getBundle("i18n");
			
			Enumeration enume = bundle.getKeys();
			String key = null;
	
			while (enume.hasMoreElements())
			{
				key = (String) enume.nextElement();
				_prop.put(key, bundle.getObject(key));
			}
			
			//log.debug("LabelManager has loaded " + _prop.size() + " labels");
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	public static String get(String propName)
	{
		String translated;
		
		if (i18n == null)
		{
			i18n = new LabelManager();
		}
        
		try{
			translated= i18n._prop.getProperty(propName);
		}
		catch (Exception e){
          //Untranslated message.
		   translated= "ERROR: UNTRANSLATED MESSAGE: " + propName;
		}
		
		
		return translated;
	}
}
