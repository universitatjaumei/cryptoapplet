package es.uji.dsign.crypto.test.digidoc;
//import org.bouncycastle.asn1.*;
import java.io.*;
import org.bouncycastle.ocsp.*;

public class Test9 {
	public static void main(String[] args) {
		String fileName = "C:\\veiko\\toolkits\\openssl\\bin\\respin.resp";
		try {
			System.out.println("Reading OCSP: " + fileName);
			FileInputStream fis = new FileInputStream(fileName);
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			byte[] data = new byte[1024];
			int n = 0;
			while((n = fis.read(data)) != -1)
				bos.write(data, 0, n);
			fis.close();
			data = bos.toByteArray();
			System.out.println("Got: " + data.length + " bytes");
			OCSPResp resp = new OCSPResp(data);
			System.out.println("Done!");
		} catch(Exception ex) {
			System.err.println("Error: " + ex);
			ex.printStackTrace(System.err);
		}
	}

}

