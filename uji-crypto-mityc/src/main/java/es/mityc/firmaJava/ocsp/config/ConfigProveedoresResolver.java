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
import java.io.IOException;
import java.io.InputStream;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/** 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ConfigProveedoresResolver implements EntityResolver, ConstantesProveedores {

	public InputSource resolveEntity(String arg0, String arg1)
			throws SAXException, IOException {

		InputSource sourceXsd = null;
		File XsdUpdated = new File (System.getProperty(USERDIR) + SEPARATOR + XSD_FILE);
		InputStream sXsd = null;
			
		if (XsdUpdated.exists()) {
			sXsd = new FileInputStream (XsdUpdated);
		} else {
			sXsd = getClass().getResourceAsStream(XSD_DEFAULT_FILE);
		}
		sourceXsd = new InputSource(sXsd);
		
		return sourceXsd;
	}

}
