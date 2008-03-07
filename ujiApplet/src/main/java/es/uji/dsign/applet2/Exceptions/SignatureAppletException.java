package es.uji.dsign.applet2.Exceptions;

import es.uji.dsign.util.i18n.LabelManager;

//TODO: implement 
public class SignatureAppletException extends Exception
{
 
	public SignatureAppletException(String messageTag)
	{
	  super(LabelManager.get(messageTag));	
	}
	
	public SignatureAppletException(String messageTag, String lineNumber)
	{
	  super("Line: " + lineNumber + "::" + LabelManager.get(messageTag));	
	}
}
