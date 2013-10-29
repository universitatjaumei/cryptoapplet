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

import java.net.URISyntaxException;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * Clase encargada de leer el fichero de configuracion de los OCSP's. 
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class ConfigProveedoresHandler 
	extends DefaultHandler implements ConstantesProveedores {

    static Log logger = LogFactory.getLog(ConfigProveedoresHandler.class);
	private boolean leyendoProveedor = false;
    private String valorTmp = EMPTY_STRING;

	private Vector<ProveedorInfo> proveedores = new Vector<ProveedorInfo>();
	private String version = EMPTY_STRING;
	private String fecha = EMPTY_STRING;
	
	public void error(SAXParseException ex)
	      throws SAXException {
			  throw ex;
	}     
	public void fatalError(SAXParseException ex)
	     throws SAXException {
		  throw ex;
	}		    
	public void warning(SAXParseException exception)
	      throws SAXException { 
		logger.warn(exception.getMessage());	  
	}
	
	public void startElement(
			final String namespace, 
			final String localname,  
		    final String type, 
		    final Attributes attributes) throws SAXException {
		
		
		if (localname.equals(NODO_PROVEEDOR)) { 
			leyendoProveedor = true;
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_NOMBRE);
			int at2 = attributes.getIndex(ATT_DESCRIPCION);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			ProveedorInfo po = new ProveedorInfo();
			
			po.setNombre(v1);
			po.setDescripcion(v2);
			proveedores.add(po);
		} else 
			if (false == leyendoProveedor) return;
		
		if (localname.equals(NODO_CA)) { 
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_NAMEHASH);
			int at2 = attributes.getIndex(ATT_PKHASH);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			((ProveedorInfo) proveedores.lastElement()).addCA 
				(
					v1, v2
				);
		}
		
		if (localname.equals(NODO_OCSP)) { 
			String v1 = EMPTY_STRING;
			String v2 = EMPTY_STRING;
			int at1 = attributes.getIndex(ATT_URI);
			int at2 = attributes.getIndex(ATT_DESCRIPCION);
			if (at1 >= 0) v1 = attributes.getValue(at1);
			if (at2 >= 0) v2 = attributes.getValue(at2);
			
			ServidorOcsp server = null;
			try {
				server = new ServidorOcsp(v1,v2);
				((ProveedorInfo) proveedores.lastElement()).addServidor(server);
			} catch (URISyntaxException e) {
				throw new SAXException (INVALID_URI + e.getMessage());
			}
		} 
	}

	public void characters(char[] ch, int start, int end) throws SAXException {
		valorTmp = new String (ch, start, end);
		valorTmp = valorTmp.trim();
	}
	public void endElement ( final String namespace, final String localname, final String type ) 
	{
		if (localname.equals(NODO_PROVEEDOR)) leyendoProveedor = false;
		if (localname.equals(NODO_VERSION)) {
			this.version = valorTmp;
		}
		if (localname.equals(NODO_FECHA)) {
			this.fecha = valorTmp;
		}
	}
	protected Vector<ProveedorInfo> getProveedores() {
		return proveedores;
	}
	protected String getFecha() {
		return fecha;
	}
	protected String getVersion() {
		return version;
	}

}
