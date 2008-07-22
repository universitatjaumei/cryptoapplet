package es.uji.dsign.crypto.verifiers;

import java.io.FileInputStream;
import java.util.Iterator;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import es.uji.dsign.crypto.test.X509KeySelector;

public class XMLDsigVerifier {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		
		// Instantiate the document to be signed.
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document doc = dbf.newDocumentBuilder().parse(new FileInputStream("servers_signed.xml"));
	
		
		// Find Signature element.
		NodeList nl =
		    doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
		
		if (nl.getLength() == 0) {
		    throw new Exception("Cannot find Signature element");
		}

		// Create a DOMValidateContext and specify a KeySelector
		// and document context.
		DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

		// Unmarshal the XMLSignature.
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature.
		boolean coreValidity = signature.validate(valContext);

		// Check core validation status.
		if (coreValidity == false) {
		    System.err.println("Signature failed core validation");
		    boolean sv = signature.getSignatureValue().validate(valContext);
		    System.out.println("signature validation status: " + sv);
		    if (sv == false) {
		        // Check the validation status of each Reference.
		        Iterator i = signature.getSignedInfo().getReferences().iterator();
		        for (int j=0; i.hasNext(); j++) {
		            boolean refValid = ((Reference) i.next()).validate(valContext);
		            System.out.println("ref["+j+"] validity status: " + refValid);
		        }
		    }
		} else {
		    System.out.println("Document Verification ok!!");
		}
		
	}

}
