package es.uji.security.crypto.jxades;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifier;
import net.java.xades.security.xml.XAdES.SignaturePolicyIdentifierImpl;
import net.java.xades.security.xml.XAdES.XAdES;
import net.java.xades.security.xml.XAdES.XAdES_EPES;
import net.java.xades.security.xml.XAdES.XMLAdvancedSignature;
import net.java.xades.util.XMLUtils;

import org.w3c.dom.Element;

import es.uji.security.crypto.ISignFormatProvider;
import es.uji.security.crypto.SignatureOptions;
import es.uji.security.util.OS;
import es.uji.security.util.i18n.LabelManager;


public class FacturaeSignatureFactory implements ISignFormatProvider
{
	private String _strerr= "";
	
	public InputStream formatSignature(SignatureOptions sopt) throws Exception
	{		
		byte[] toSign= OS.inputStreamToByteArray(sopt.getToSignInputStream());
		X509Certificate sCer= sopt.getCertificate();
		PrivateKey pk= sopt.getPrivateKey();
		
		ByteArrayInputStream originalData = new ByteArrayInputStream(toSign);
	   
		if (sCer == null)
	    {
			_strerr= LabelManager.get("ERROR_FACTURAE_NOCERT");
			return null;
	    }
	       
	                  
		if ( pk == null ){
			_strerr= LabelManager.get("ERROR_FACTURAE_NOKEY");
			return null;
		}
		
		try{
			
			// Load XML data
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Element element = db.parse(originalData).getDocumentElement();

			// Create a XAdES-EPES profile		
			
			XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, element);


			// SigningCertificate
			// Check the certificate validity (local)
			
			try{
	          	sCer.checkValidity();
	        }
			
	        catch(CertificateException cex){
	          	_strerr= LabelManager.get("ERROR_CERTIFICATE_EXPIRED");
	          	return null;
	        }
	        
			xades.setSigningCertificate(sCer);
			
			SignaturePolicyIdentifier spi = new SignaturePolicyIdentifierImpl(false);

			//Set SignaturePolicyIdentifier
			
			spi.setIdentifier("http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf");		
			spi.setDescription("Pol\u00edtica de firma electr\u00f3nica para facturaci\u00f3n electr\u00f3nica con formato Facturae");

			xades.setSignaturePolicyIdentifier(spi);
			
			//Sign data
			
			XMLAdvancedSignature xmlSignature = XMLAdvancedSignature.newInstance(xades);
			
			try
			{
				xmlSignature.sign(sCer, pk, Arrays.asList(new String[] { "" }), "S0", "http://tss.accv.es:8318/tsa");
			}			
			catch (MarshalException me){
				_strerr=LabelManager.get("ERROR_FACTURAE_SIGNATURE");
				me.printStackTrace();
				return null;
			}
            catch (XMLSignatureException xmlse){
            	_strerr=LabelManager.get("ERROR_FACTURAE_SIGNATURE");
				xmlse.printStackTrace();
				return null;
            }
            catch (GeneralSecurityException gse){
            	_strerr=LabelManager.get("ERROR_FACTURAE_SIGNATURE"); 
				gse.printStackTrace();
				return null;
            }
            
			// Return Results
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			
			BufferedOutputStream bos = new BufferedOutputStream(out);
			
			XMLUtils.writeXML(bos, xmlSignature.getBaseElement(), false);
			
			bos.flush();
			
			
			return new ByteArrayInputStream(out.toString().getBytes()); 
		}
		
		catch (Exception e ){	
			e.printStackTrace();
			return null;
		}
			
	}
	
	public String getError(){
		return _strerr;
	}
}
