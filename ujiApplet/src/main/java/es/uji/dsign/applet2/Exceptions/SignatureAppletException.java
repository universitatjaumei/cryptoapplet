package es.uji.dsign.applet2.Exceptions;

import es.uji.dsign.util.i18n.LabelManager;

//TODO: implement 
public class SignatureAppletException extends Exception
{
    String message;
    
	public SignatureAppletException(String messageTag)
	{
	  message= LabelManager.get(messageTag);
	}
	
	public SignatureAppletException(String messageTag, boolean translate)
	{
	 if (translate)
		 message= LabelManager.get(messageTag);
	 else
		 message= messageTag;
	}
	
	public String getMessage(){
		return message;
	}
	
	public SignatureAppletException(String messageTag, String lineNumber)
	{
	  super("Line: " + lineNumber + "::" + LabelManager.get(messageTag));	
	}
}
