package es.uji.dsign.applet2.io;

import es.uji.dsign.applet2.SignatureApplet;

import java.util.Hashtable;

public class ParamInputData extends AbstractData implements InputParams{

	private String str_in; 
	
	public ParamInputData(String in){
		this.str_in= in;
	}
	
	public String getInput()
	{
		return this.str_in;
	}
		
	public int getInputCount() throws Exception {
		// TODO Auto-generated method stub
		return 1;
	}

	public byte[] getSignData() throws Exception {
		
		if (mustHash)
			return this.getMessageDigest(this.str_in.getBytes());
		
		return this.str_in.getBytes();
	}

	public byte[] getSignData(int item) throws Exception {
		// TODO Auto-generated method stub
		return null;
	}

	public String getSignFormat(SignatureApplet base) {
		// TODO Auto-generated method stub
		return null;
	}

	public void initialize(Hashtable<String, Object> props) {
		// TODO Auto-generated method stub
		
	}

	public void flush() {
		// TODO Auto-generated method stub
		
	}

}
