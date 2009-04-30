package es.uji.security.crypto.cms;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Vector;

public class CMSTSSignatureVerifier {
	
	//TODO: Implement this ...
	public static boolean verifyTS(String[] tsaPaths, InputStream bsig, InputStream bts){
		
		return false;
	}
	
	
	public static void main(String[] args) {

		Vector<String> caPaths= new Vector<String>();
		Vector<String> tsaPaths= new Vector<String>();
		String cmsFile=null, dataFile=null;

		try{
			if( args.length == 0 ){
				System.err.println("Uso: CMSSignatureVerifier -tsa0 root_tsa_ca -tsa1 root_tsa_level2_ca ... -ca0 root_ca -ca1 level2_ca -ca2 level3_ca ... -data data.txt -cms cms.pem");
				System.exit(-1);
			}
			int n_ca=0;
			int n_tsa_ca=0;
			for ( int i=0; i<args.length; i++ ){
				try{
					if (args[i].startsWith("-ca")){
						int aux= Integer.parseInt(args[i].substring(3));
						if (aux != n_ca){
							throw new Exception("CA args not in order");
						}
						caPaths.add(args[i+1]);
						n_ca++;
					}
					else if (args[i].startsWith("-tsa")){
						int aux= Integer.parseInt(args[i].substring(4));
						if (aux != n_tsa_ca){
							throw new Exception("TSA CA args not in order");
						}
						tsaPaths.add(args[i+1]);
						n_tsa_ca++;
					}
					else if (args[i].equals("-data")){
						dataFile= args[i+1];
					}
					else if (args[i].equals("-cms")){
						cmsFile= args[i+1];
					}
				}
				catch (Exception e){
					e.printStackTrace();
					System.err.println("Uso: CMSSignatureVerifier -ca0 root_ca -ca1 level2_ca -ca2 level3_ca ... -data data.txt -cms cms.pem");
					System.exit(-1);
				}
			}

			FileInputStream fis= new FileInputStream(cmsFile);
			byte[] b= new byte[fis.available()];
			fis.read(b);
			
			String straux= new String(b); 
			String sig= straux.substring(straux.indexOf("<cms_signature>" + 15), straux.indexOf("</cms_signature>"));
			String ts= straux.substring(straux.indexOf("<cms_timestamp>" + 15), straux.indexOf("</cms_timestamp>"));
			
			ByteArrayInputStream bsig= new ByteArrayInputStream(sig.getBytes()); 
			ByteArrayInputStream bts= new ByteArrayInputStream(ts.getBytes());
			
			//Split the resulting signature into signed signature cms and signed timestamp cms	    
			System.out.println("Signature validation ... ");
			String[] x= new String[0];
			CMSSignatureVerifier pv= new CMSSignatureVerifier(caPaths.toArray(x),new FileInputStream(dataFile),bsig);
			System.out.println("Resultado verificacion Firma: " + pv.verifyPkcs7());
			System.out.print("SHA-1:");
			CMSSignatureVerifier.hexPrint(pv.SHA1Digest());
			System.out.println("DN del firmante: " + pv.getX509SubjectName());
			System.out.println("X509 User Cert: " + pv.getX509Certificate());

			//Verification of the ts: 
			System.out.println("TS validation ... ");
			System.out.println("Resultado verificacion Firma: " + verifyTS(tsaPaths.toArray(x),bsig, bts));
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
