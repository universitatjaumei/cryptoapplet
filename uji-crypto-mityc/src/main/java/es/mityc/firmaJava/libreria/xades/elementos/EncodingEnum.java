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
 * 51 Franklin Street, 5º Piso, Boston, MA 02110-1301, USA.
 * 
 */
package es.mityc.firmaJava.libreria.xades.elementos;

import java.net.URI;
import java.net.URISyntaxException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 1.0
 */
public enum EncodingEnum {
	
	DER_ENCODED("http://uri.etsi.org/01903/v1.2.2#DER"),
	BER_ENCODED("http://uri.etsi.org/01903/v1.2.2#BER"),
	CER_ENCODED("http://uri.etsi.org/01903/v1.2.2#CER"),
	PER_ENCODED("http://uri.etsi.org/01903/v1.2.2#PER"),
	XER_ENCODED("http://uri.etsi.org/01903/v1.2.2#XER");
	
	private final static Log logger = LogFactory.getLog(EncodingEnum.class);
	
	private URI uri;
	
	private EncodingEnum(String uri) {
		try {
			this.uri = new URI(uri);
		} catch (URISyntaxException ex) {
			Log logger = LogFactory.getLog(EncodingEnum.class);
			logger.error("Error creando enumerado de encoding", ex);
		}
	}
	
	public URI getEncodingUri() {
		return uri;
	}
	
	public static EncodingEnum getEncoding(String uri) {
		try {
			URI temp = new URI(uri);
			if (temp.equals(DER_ENCODED.uri))
				return DER_ENCODED;
			else if (temp.equals(BER_ENCODED.uri))
				return BER_ENCODED;
			else if (temp.equals(CER_ENCODED.uri))
				return CER_ENCODED;
			else if (temp.equals(PER_ENCODED.uri))
				return PER_ENCODED;
			else if (temp.equals(XER_ENCODED.uri))
				return XER_ENCODED;
		} catch (URISyntaxException ex) {
			if (logger.isDebugEnabled())
				logger.debug("Encoding indicado no es una URI", ex);
			return null;
		}
		return null;
	}

}
