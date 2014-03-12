/**
 * LICENCIA LGPL:
 * 
 * Esta librería es Software Libre; Usted puede redistribuirlo y/o modificarlo
 * bajo los términos de la GNU Lesser General Public License (LGPL)
 * tal y como ha sido publicada por la Free Software Foundation; o
 * bien la versión 2.1 de la Licencia, o (a su elección) cualquier versión posterior.
 * 
 * Esta librería se distribuye con la esperanza de que sea útil, pero SIN NINGUNA
 * GARANTÍA; tampoco las implícitas garantías de MERCANTILIDAD o ADECUACIÓN A UN
 * PROPÓSITO PARTICULAR. Consulte la GNU Lesser General Public License (LGPL) para más
 * detalles
 * 
 * Usted debe recibir una copia de la GNU Lesser General Public License (LGPL)
 * junto con esta librería; si no es así, escriba a la Free Software Foundation Inc.
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA o consulte
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2008 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ocsp.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;

import javax.xml.XMLConstants;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1OctetString;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXNotRecognizedException;
import org.xml.sax.SAXNotSupportedException;


/**
 * Obtiene la lista de proveedores OCSP's configurados. 
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ConfigProveedores 
	implements ConstantesProveedores, Cloneable
{
    private static Log logger = LogFactory.getLog(ConfigProveedores.class);
	private Vector<ProveedorInfo> proveedores  = null;
	private String version = EMPTY_STRING;
	private String fecha = EMPTY_STRING;
	
	/**
	 * Constructor de la clase.
	 */
	public ConfigProveedores(){
		proveedores = new Vector<ProveedorInfo> ();
	}

	protected Object clone() throws CloneNotSupportedException {
		ConfigProveedores copy = (ConfigProveedores) super.clone();
		copy.version = version;
		copy.fecha = fecha;
		int totalProveedores = proveedores.size();
		for (int i=0;i<totalProveedores;i++ ){
			copy.proveedores.add((ProveedorInfo)proveedores.get(i).clone());
		}
		return copy;
	}

	private InputSource getConfigFile () throws FileNotFoundException {
		InputSource sourceXml = null;
		File XmlUpdated = new File (System.getProperty(USERDIR) + SEPARATOR +  XML_FILE);
		InputStream sXml = null;
			
		if (XmlUpdated.exists()) {
			sXml = new FileInputStream (XmlUpdated);
		} else {
			sXml = getClass().getResourceAsStream(XML_DEFAULT_FILE);
		}
		sourceXml = new InputSource(sXml);
		return sourceXml;
	}
	
	/**
	 * Lee el fichero de configuracion para obtener la lista de proveedores OCSP
	 * @return true si la operacion fue correcta, false en otro caso
	 * @throws SAXException Si el XML es erroneo o no es válido. 
	 */
	public boolean read() throws SAXException {

		boolean ok = false;
		ConfigProveedoresHandler reader = new ConfigProveedoresHandler();
		
		SAXParserFactory spf = SAXParserFactory.newInstance();
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.XML_NS_URI);
		spf.setSchema(sf.newSchema(new StreamSource(this.getClass().getResourceAsStream("/OCSPServersInfo.xsd"))));
		spf.setNamespaceAware(true);
//		spf.setValidating(true);
		
		
		try {
			javax.xml.parsers.SAXParser parser = spf.newSAXParser();

			// Perform namespace processing
//			parser.setFeature(FEATURE_NAMESPACES, true);
//			parser.setFeature(FEATURE_VALIDATION, true);
//			parser.setFeature(FEATURE_SCHEMA, true);
//
//			parser.setEntityResolver(new ConfigProveedoresResolver());
//			parser.setErrorHandler(reader);
//			parser.setContentHandler(reader);
//			parser.parse(getConfigFile());
			parser.parse(getConfigFile(), reader);
			
			proveedores = reader.getProveedores();
			version = reader.getVersion();
			fecha = reader.getFecha();
			ok = true;
		
		} 
		catch (FileNotFoundException e) { 
            logger.error(IO_EXCEPTION + e.getMessage());
            if (logger.isDebugEnabled())
            	logger.debug(e);
		} 
		catch (SAXNotRecognizedException e) {
            logger.error(e.getMessage());			
            if (logger.isDebugEnabled())
            	logger.debug(e);
		}
		catch (SAXNotSupportedException e) {
            logger.error(e.getMessage());	
            if (logger.isDebugEnabled())
            	logger.debug(e);
		}
		catch (IOException e) { 
            logger.error(IO_EXCEPTION + e.getMessage());	
            if (logger.isDebugEnabled())
            	logger.debug(e);
		} catch (ParserConfigurationException ex) {
            logger.error(ex.getMessage());	
            if (logger.isDebugEnabled())
            	logger.debug(ex);
		}  
		return ok;
	
	}

	/**
	 * Obtiene el proveedorOcsp configurado para el certificado indicado
	 * @param Object Certificado del que se quiere obtener los datos del OCSP.
	 * 			Puede ser del tipo String, byte[], o X509Certificate
	 * @return ProveedorInfo encontrado o null otro caso 
	 */
	public ProveedorInfo buscarProveedor (Object certObj) {
		X509Certificate cert = null;
		
		if (certObj == null) {
			logger.error(CERTIFICATE_TYPE_EXCEPTION);
			return null;
		}
		
		try {
			if (certObj instanceof byte[]) {
				cert = UtilidadesX509.getCertificate((byte[])certObj);
			} else if (certObj instanceof String) {
				cert = UtilidadesX509.getCertificate((String)certObj);
			} else if (certObj instanceof X509Certificate) {
				cert = (X509Certificate)certObj;
			} else {
				logger.error(CERTIFICATE_TYPE_EXCEPTION);
				return null;
			}
		} catch (CertificateException e) {
			logger.error(CERTIFICATE_EXCEPTION, e);
		}
		ProveedorInfo buscado = null;
		String nameHash = EMPTY_STRING;
		String pkHash = EMPTY_STRING;
		try {

			ASN1OctetString issuerNameHash = UtilidadesX509.getIssuerNameHash(cert);
			ASN1OctetString issuerKeyHash = UtilidadesX509.getIssuerKeyHash(cert);

			nameHash = issuerNameHash.toString().replace(ALMOHADILLA, EMPTY_STRING);
			pkHash = issuerKeyHash.toString().replace(ALMOHADILLA, EMPTY_STRING);

			buscado = buscarProveedor(nameHash,pkHash);
		} catch (IOException ex) {
			logger.error(ex.getMessage());
		}
		return buscado;
	}

	/**
	 * Obtiene el proveedorOcsp configurado para los datos indicados
	 * @param nameHash
	 * @param pkHash
	 * @return ProveedorInfo encontrado o null otro caso
	 */
	protected ProveedorInfo buscarProveedor (String nameHash, String pkHash) {
		if (null == proveedores) return null;
		int totalProveedores = proveedores.size();
		ProveedorInfo poBuscado = null;
		for (int i=0;i<totalProveedores;i++ ){
			if (proveedores.get(i).puedeValidar(nameHash, pkHash))
				poBuscado = proveedores.get(i);
		}
		return poBuscado;
	}

	/**
	 * Obtiene la fecha del fichero de configuracion
	 */
	public String getFecha() {
		return fecha;
	}
	/**
	 * Obtiene la version del fichero de configuracion
	 */
	public String getVersion() {
		return version;
	}

	/**
	 * Obtiene la lista completa de proveedores del fichero de configuracion.
	 */
	public Vector<ProveedorInfo> getProveedores() {
		return (Vector<ProveedorInfo>) proveedores.clone();
		
	}
	

	private static ConfigProveedores configCacheado = null;
	
	/**
	 * Obtiene el primer Servidor ocsp de la lista de servidores con los que se puede validar el certificado indicado.
	 * @param cert
	 * @return ServidorOcsp encontrado. Null en otro caso.
	 */
	public static ServidorOcsp getServidor(X509Certificate cert){
		ServidorOcsp servidorOcsp = null;
		try {
			ConfigProveedores config = null;
	       	 if (null == configCacheado) {
	       		 config = new ConfigProveedores();
	       		if (!config.read()) return null;
	       		
	       		configCacheado = config;
	       	 }
	       	 else config = configCacheado;
	       	 
	       	 ProveedorInfo proveedor = config.buscarProveedor(cert);
   			 if (null == proveedor) return null; 
   			servidorOcsp = proveedor.getServidor();

			} catch (SAXException e) {
				logger.error (e.getMessage());
				if (logger.isDebugEnabled())
					logger.debug(e);
			}
			return servidorOcsp;
	}
	/**
	 * Obtiene la lista de servidores con los que se puede validar el certificado indicado.
	 * @param cert
	 * @return ServidorOcsp encontrado. Null en otro caso.
	 */
	public static Vector<ServidorOcsp> getServidores(X509Certificate cert) {
		Vector<ServidorOcsp>  servidores = null;
		try {
	       	 ConfigProveedores config = null;
	       	 if (null == configCacheado) {
	       		 // AppPerfect: falso positivo
	       		 config = new ConfigProveedores();
	       		if (!config.read()) return null;
	       		configCacheado = config;
	       	 }
	       	 else config = configCacheado;
	       	 
   			 ProveedorInfo proveedor = config.buscarProveedor(cert);
   			 if (null == proveedor) return null; 
   			 servidores = proveedor.getServidores();

			} catch (SAXException e) {
				logger.error (e.getMessage());
			}
			return servidores;
	}
	
}
