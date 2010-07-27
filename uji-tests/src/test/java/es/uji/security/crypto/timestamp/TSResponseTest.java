package es.uji.security.crypto.timestamp;

import java.io.FileInputStream;
import java.io.IOException;

import es.uji.security.crypto.config.OS;

public class TSResponseTest
{
    public static String baseDir = "src/main/resources/";

    public static void main(String[] args) throws IOException
    {
        for (String fileName : new String[] { "ts_response_1.bin", "ts_response_2.bin","bueno.bin"})
    	
        {
            try
            {
                new TSResponse(OS.inputStreamToByteArray(new FileInputStream(TSResponseTest.baseDir
                        + fileName)));
                System.out.println("Response ok");
            }
            catch (Exception e)
            {
            	e.printStackTrace();	
            	System.out.println("Error parseando respuesta: " + e.getMessage());
            }
        }
    }
}	
