package es.uji.dsign.applet2.io;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class AbstractInputData {
	
	boolean mustHash=false;
	
	public static byte[] getMessageDigest(byte[] toHash){
		byte[] digest= null;
		
		
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(toHash);

			digest = md.digest();
			md.reset();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			//      Null will be returned
			// e.printStackTrace();
		}
		
		return digest;
	}
	
	public void setmustHash(boolean value)
	{
		this.mustHash= value;
	}
	
	//Test
	public static void main(String[] args){
		System.out.println(es.uji.dsign.util.HexDump.xdump(getMessageDigest("a".getBytes())));
	}
}
