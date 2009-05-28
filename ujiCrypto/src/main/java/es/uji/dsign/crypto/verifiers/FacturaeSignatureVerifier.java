package es.uji.dsign.crypto.verifiers;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Properties;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import net.java.jxades.security.xml.SignatureStatus;
import net.java.jxades.security.xml.ValidateResult;
import net.java.jxades.security.xml.XAdES.XAdES;
import net.java.jxades.security.xml.XAdES.XAdES_EPES;
import net.java.jxades.security.xml.XAdES.XMLAdvancedSignature;

import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import es.uji.dsign.crypto.digidoc.utils.ConfigManager;
import es.uji.dsign.util.ConfigHandler;
import es.uji.dsign.util.OS;

public class FacturaeSignatureVerifier {

	private static String validarXmlvsXsd(String datosXML, String sFichXsd) throws URISyntaxException
    {
     //boolean bIsXmlOk           = false;
        boolean NAME_SPACE_AWARE   = true;
        boolean VALIDATING         = true;
        String SCHEMA_LANGUAGE     = "http://java.sun.com/xml/jaxp/properties/schemaLanguage";
        String SCHEMA_LANGUAGE_VAL = "http://www.w3.org/2001/XMLSchema";
        String SCHEMA_SOURCE       = "http://java.sun.com/xml/jaxp/properties/schemaSource";
        String sCtrlErr  ="";
       
        try
	     {	
	    	 	
	    	 	ClassLoader cl = FacturaeSignatureVerifier.class.getClassLoader(); 
	    	 	InputStream is = cl.getResourceAsStream(sFichXsd);
	    	 	//InputStream is = cl.getResourceAsStream("data.xml");
	    	 	
	    	 	/*
	    	 	if (is == null){
	    	 		System.out.println("no carga");
	    	 	}
	    	 	*/
	    	 	Reader xmlReader=new StringReader(datosXML);
	    	 	Reader xsdReader = new InputStreamReader(is);
	    	 	
	            SAXParserFactory factory = SAXParserFactory.newInstance();
	           
	             // Configure SAXParserFactory to provide parsers that are namespace aware.
	            factory.setNamespaceAware(NAME_SPACE_AWARE);
	           
	            // Configure SAXParserFactory to provide parsers that are validating. This property
	            // must have the value true for any of the property strings defined below to take
	            // effect.
	            factory.setValidating(VALIDATING);
	            SAXParser parser = factory.newSAXParser();
	           
	            // Setting the schema language for xml schema validation
	            parser.setProperty(SCHEMA_LANGUAGE, SCHEMA_LANGUAGE_VAL);
	            // Setting the schema source for xml schema validation
	            //parser.setProperty(SCHEMA_SOURCE, new InputSource(xsdReader));
	            parser.setProperty(SCHEMA_SOURCE, new InputSource(xsdReader));
	           
	            DefaultHandler handler = new XmlDefaultHandler();
	            
	            parser.parse(new InputSource(xmlReader), handler);
	            
	            // si procesa todo el metodo sin producir excepcion, el fichero xml
	            // es correcto.
	            //bIsXmlOk = true;
	     }
     catch (FactoryConfigurationError    e)  {  sCtrlErr = "{" + e.toString() + "}. ";/*System.out.println(sCtrlErr);*/}
     catch (ParserConfigurationException e)  {  sCtrlErr = "{" + e.toString() + "}. ";/*System.out.println(sCtrlErr);*/}
     catch (SAXException e)                  {  sCtrlErr = "{" + e.toString() + "}. ";/*System.out.println(sCtrlErr);*/}
     catch (IOException e)                   {  sCtrlErr = "{" + e.toString() + "}. ";/*System.out.println(sCtrlErr);*/}
     
     return sCtrlErr;
    } 
 
 public static class XmlDefaultHandler extends DefaultHandler
 {
        /** @see org.xml.sax.ErrorHandler#error(SAXParseException)*/
        public void error(SAXParseException spe) throws SAXException
        
  {			/*System.out.println("error");*/
            throw spe;
        }
        /** @see org.xml.sax.ErrorHandler#fatalError(SAXParseException)*/
        public void fatalError(SAXParseException spe) throws SAXException
  {	
        	/*System.out.println("fatalError");*/
            throw spe;
        }
 }
	
	public FacturaeSignatureVerifier()
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
			Properties prop= ConfigHandler.getProperties();
			if ( prop != null ){
				ConfigManager.init(prop);
			}
			else{
				return null;
			}
	
			// Validacion contra el esquema
			
			byte [] aux = OS.inputStreamToByteArray(in);
			
			in.read(aux);
			
			String datosXML = new String(aux);
			
			
			String strXSD30 = new String("facturae30.xsd");
			String strXSD31 = new String("facturae31.xsd");
						
			String is30 = "";
			String is31 = "";
			
			is30 = validarXmlvsXsd(datosXML, strXSD30);
			is31 = validarXmlvsXsd(datosXML, strXSD31);
			
			if (is30!= "" && is31!= ""){
				 return new String[] {"Invalid Facturae Format"};
			}
			
		
			// Verificacion
			
			ByteArrayInputStream originalData = new ByteArrayInputStream(aux);
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			//Element element = db.parse(new File("enveloped-out.xml")).getDocumentElement();
			Element element = db.parse(originalData).getDocumentElement();

			// Create a XAdES-C profile
			XAdES_EPES xades = (XAdES_EPES) XAdES.newInstance(XAdES.EPES, element);

			XMLAdvancedSignature fileXML = XMLAdvancedSignature.newInstance(xades);
			List<SignatureStatus> st = fileXML.validate();

			boolean error = false;
			String res= new String("");
			
			for (SignatureStatus status : st)
			{
				if (status.getValidateResult() != ValidateResult.VALID)
				{
					res = res.concat(status.getReasonsAsText());
					error = true;
				}
			}

			if (!error)
			{
				/*System.out.println("Ok");*/
				return null;
			}
			else{
				return new String[] {res};
			}
		}
			
			
		catch(Exception e ){
			e.printStackTrace();
			return new String[] {e.getMessage()};
		}
	  }
}
