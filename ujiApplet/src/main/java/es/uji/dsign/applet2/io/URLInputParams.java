package es.uji.dsign.applet2.io;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

import javax.swing.JApplet;

import es.uji.dsign.util.OS;

import es.uji.dsign.applet2.SignatureApplet;

public class URLInputParams extends AbstractInputData implements InputParams
{
	boolean initialized= false; 
	int count= 0, current=0;
	String[] inputs; 
		
	public URLInputParams(String[] sources)
	{
		inputs= sources;
		count= sources.length;
		initialized= true;
	}
	
	public int getInputCount() throws Exception
	{
		if ( ! initialized )
			throw new IOException("Uninitialized Input method");
	
		return count;	
	}
	
	public byte[] getSignData() throws Exception
	{
		
		URL url = new URL(inputs[current]);
		URLConnection uc = url.openConnection();
		uc.connect();
		InputStream in = uc.getInputStream();
		
		current++;
		
		return OS.inputStreamToByteArray(in);
	}
	
	public byte[] getSignData(int item) throws Exception
	{
		if ( ! initialized )
			throw new IOException("Uninitialized Input method");
		
		if ( item >= count )
			throw new IOException("Item count length exceeded");
		
		System.out.println("INPUTS: " + inputs[item]);
		
		URL url = new URL(inputs[item]);
		URLConnection uc = url.openConnection();
		uc.connect();
		InputStream in = uc.getInputStream();
		
		if (mustHash)
			return this.getMessageDigest(OS.inputStreamToByteArray(in));

		return OS.inputStreamToByteArray(in);
	}


	public String getSignFormat(SignatureApplet base)
	{
		return (base.getParameter("signFormat") != null) ? base.getParameter("signFormat") : "es.uji.dsign.crypto.CMSSignatureFactory";
	}

	public void flush() {
		current= 0;
	}
}