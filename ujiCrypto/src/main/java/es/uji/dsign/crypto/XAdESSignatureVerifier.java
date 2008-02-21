package es.uji.dsign.crypto;

import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;

import es.uji.dsign.crypto.digidoc.DigiDocException;
import es.uji.dsign.crypto.digidoc.Signature;
import es.uji.dsign.crypto.digidoc.SignedDoc;
import es.uji.dsign.crypto.digidoc.factory.DigiDocFactory;
import es.uji.dsign.crypto.digidoc.utils.ConfigManager;

public class XAdESSignatureVerifier {

	public XAdESSignatureVerifier()
	{

	}

	public String[] verifyUrl(String strUrl)
	{
		try{

			URL url = new URL(strUrl);
			URLConnection uc = url.openConnection();
			uc.connect();
			InputStream in = uc.getInputStream();
			return verify(in);
		}
		catch (Exception e){
			e.printStackTrace();
			return new String[] {e.getMessage()};
		}
	}

	public String[] verify(InputStream in){		

		try{
			String BASE = "jar://"; 
			ConfigManager.init(BASE + "jdigidoc.cfg");
			DigiDocFactory digFac = ConfigManager.instance().getDigiDocFactory();
			SignedDoc sdoc= digFac.readSignedDoc(in);


			Signature sig;

			for (int i=0 ; i<sdoc.countSignatures() ; i++) 
			{
				sig = sdoc.getSignature(i);
				ArrayList errs = sig.verifyOcspOrCrl(sdoc, false, false);
				if(errs.size() == 0)
				{
					return null;
				}

				String[] outErrs= new String[errs.size()];
				for (int j=0 ; j<errs.size() ; j++)
				{
					outErrs[j]= ((DigiDocException) errs.get(j)).getMessage();
				}
				return outErrs;
			}
		}

		catch (Exception e){
			e.printStackTrace();
			return new String[] {e.getMessage()};
		}

		return new String[] { "No signatures" };

	}
}
