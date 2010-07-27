package es.uji.security.crypto.timestamp;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;


public class TSResponseTest {

	public static String baseDir = "src/main/resources/";

	public static void main(String[] args) throws IOException{
		
		FileInputStream fts1 = new FileInputStream(TSResponseTest.baseDir + "ts_response_1.bin");
		FileInputStream fts2 = new FileInputStream(TSResponseTest.baseDir + "ts_response_2.bin");
		
		byte[] bts1= new byte[fts1.available()];
		byte[] bts2= new byte[fts2.available()];
		
		fts1.read(bts1);
		fts2.read(bts2);
		
		 
		try{
			TSResponse ts1= new TSResponse(bts1); 
		}
		catch(Exception e){
			System.out.println("Parsing de ts1 ha fallado: " + e.getMessage());
		}

		try{
			TSResponse ts2= new TSResponse(bts2);
		}
		catch(Exception e){
			System.out.println("Parsing de ts2 ha fallado: " + e.getMessage());
		}
	}
}
