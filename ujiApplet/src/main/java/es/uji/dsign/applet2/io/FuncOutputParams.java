package es.uji.dsign.applet2.io;

import java.io.IOException;
import java.util.Hashtable;

import es.uji.dsign.applet2.SignatureApplet;
import es.uji.dsign.util.Base64;

public class FuncOutputParams implements OutputParams {
    private String fun, onSignOk="onSignOk";
    private byte[] bstrSig= null, bstrAux= null;
    private String strSig= null;
    SignatureApplet sap;
        
	public FuncOutputParams(SignatureApplet sap, String onSignOk)
	{
		this.onSignOk= onSignOk;
		this.sap= sap;
	}
	
	public void setSignData(byte[] data)
			throws IOException {
		String strAux = new String(Base64.encode(data));
                System.out.println("coding to B64 ");
		int i = 0;
		int len= strAux.length();
	        bstrAux= strAux.getBytes();
 		int mod= len % 64; 
		
		if (mod==0)
                    bstrSig= new byte[(len + len/64)-1];
		else
		    bstrSig= new byte[len + len/64];

 		int j=0;

		for (i = 0; i < len; i++)
		{
 		   if (i%64 == 0 && i != 0){
                      bstrSig[j++]= '\n';
		   }
                   bstrSig[j++]= bstrAux[i];
		   
		}
		strSig= new String(bstrSig);
                System.out.println("coded to B64 ");
	}

	public void setSignFormat(Hashtable<String, Object> params,
			byte[] signFormat) throws IOException {
		// TODO Auto-generated method stub
		
	}

	public void setSignFormat(byte[] signFormat) 
	throws IOException
	{
		// TODO Auto-generated method stub
		
	}

	public void signOk()
	{
		System.out.println("Invoking onSignOk: " + this.onSignOk );
		if (strSig!="")
			netscape.javascript.JSObject.getWindow(sap).call(this.onSignOk, new String[] { strSig });
	}
	
	public void flush()
	{
		// TODO Auto-generated method stub
		
	}

}
