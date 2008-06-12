package es.uji.dsign.crypto;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;

import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;

import es.uji.dsign.util.Base64;

public class TimeStampFactory {

    private static int CONN_TIMEOUT= 5000;
	
	public static byte[] getTimeStamp(String strUrl, byte[] hash){
	
		TimeStampResponse resp= null;
		TimeStampRequest request= null;
		
		try{
			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			reqGen.setCertReq(false);

			request = reqGen.generate(TSPAlgorithms.SHA1, hash);
			byte[] enc_req = request.getEncoded();

			URL url = new URL(strUrl);

			URLConnection urlConn = url.openConnection();
			urlConn.setConnectTimeout(CONN_TIMEOUT);
			urlConn.setReadTimeout(CONN_TIMEOUT);
			urlConn.setDoInput(true);
			urlConn.setDoOutput(true);
			urlConn.setUseCaches(false);

			urlConn.setRequestProperty("Content-Type", "application/timestamp-query");
			urlConn.setRequestProperty("Content-Length", "" + enc_req.length);

			OutputStream printout = urlConn.getOutputStream();
			printout.write(enc_req);
			printout.flush();
			printout.close();

			InputStream in = urlConn.getInputStream();				

			resp = new TimeStampResponse(in);
			
			try{
				resp.validate(request);
			}
			catch (TSPException ex){
				ex.printStackTrace();
				return null;
			}
			
			return resp.getEncoded();
		} 
		catch (SocketTimeoutException ex){
			ex.printStackTrace();
			return null;
		}
		catch (Exception e){
			e.printStackTrace();
			return null; 
		}
	}

	
	/**
	 * Main for testing porpouses only ...
	 * @param args
	 */
	public static void main(String[] args) {
		
		try{
			TimeStampResponse tsr= new TimeStampResponse(getTimeStamp("http://tss.accv.es:8318/tsa",
					new byte[]{(byte)0x99,(byte)0x80,(byte)0x0b,(byte)0x85,(byte)0xd3,(byte)0x38,(byte)0x3e,(byte)0x3a,(byte)0x2f,(byte)0xb4,(byte)0x5e,(byte)0xb7,(byte)0xd0,(byte)0x06,(byte)0x6a,(byte)0x48,(byte)0x79,(byte)0xa9,(byte)0xda,(byte)0xd0}));
			System.out.println(new String(Base64.encode(tsr.getEncoded())));
		} 
		catch(Exception e){
			e.printStackTrace();
		}
		
	}	
}
