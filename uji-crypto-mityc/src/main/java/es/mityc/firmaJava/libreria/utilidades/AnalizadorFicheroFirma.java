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

package es.mityc.firmaJava.libreria.utilidades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.xml.sax.Attributes;
import org.xml.sax.Locator;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.helpers.DefaultHandler;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class AnalizadorFicheroFirma extends DefaultHandler implements ConstantesXADES{

	private ArrayList ficheros = new ArrayList();
	private boolean procesando = false;
	private OutputStream os = null;
	
    static Log log = 
        LogFactory.getLog(AnalizadorFicheroFirma.class);
	
	public void setDocumentLocator(Locator loc) {}

	public void startDocument() {}

	public void endDocument() {
		//FicherosFirma.getInstance();
		File[] arrayFicheros = new File[ficheros.size()];
		ficheros.toArray(arrayFicheros);
		FicherosFirma.setFicheros(arrayFicheros);
		os = null;
		ficheros = null;
	}

	public void processingInstruction(String destino, String datos) {
	}

	public void startPrefixMapping(String prefijo, String uri) {
	}

	public void endPrefixMapping(String prefijo) {
	}

	public void startElement(String espacioNombres, String nomLocal,
			String nomCompleto, Attributes atrs) {
		String id = null;
		int longitud = atrs.getLength();
		for (int i = 0; i < longitud; i++) {
			if (ID.equals(atrs.getLocalName(i))) {
				id = atrs.getValue(i);
			}
		}
		if ((PARTS.equals(nomLocal)) && (PARTS.equals(nomCompleto))) {
			procesando = true;
			try {
				File fichero = File.createTempFile(id+GUION, GUION_TEMPORAL);
				ficheros.add(fichero);
				os = new FileOutputStream(fichero);
			} catch (IOException e) {
				e.printStackTrace();
			}

		}	
	}

	public void endElement(String espacio, String nomLocal, String nomCompleto) {
		if ((PARTS.equals(nomLocal)) && (PARTS.equals(nomCompleto))) {
			procesando = false;
			try {
				os.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public void characters(char[] ch, int inicio, int longitud) {
		if (procesando) {
			String cad = new String(ch, inicio, longitud);
			try {
				os.write(cad.getBytes(), 0, longitud);
			} catch (IOException e) {
				e.printStackTrace();
			}
			cad = null;
		}
	}

	public void ignorableWhitespace(char[] ch, int comienzo, int fin) {
	}

	public void skippedEntity(String nombre) {
	}
	

	
	public void error(SAXParseException exc) throws SAXException {
		mostrarError(exc, I18n.getResource(LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_1));
		log.error(I18n.getResource(LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_1) + exc);
	}

	public void fatalError(SAXParseException exc) throws SAXException {
		mostrarError(exc, I18n.getResource(LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_2));
		log.fatal(I18n.getResource(LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_2) + exc);
	}

	public static void mostrarError(SAXParseException exc, String aviso)
			throws SAXException {
		log.error(aviso); 
		log.error(LINE_DOS_PUNTOS + exc.getLineNumber());
		log.error(URI_DOS_PUNTOS + exc.getSystemId());
		log.error(I18n.getResource(LIBRERIA_UTILIDADES_ANALIZADOR_ERROR_3) + exc.getMessage());
		throw new SAXException(aviso);
	}

	public void analizar(File fichero) {
		SAXParserFactory factoria = SAXParserFactory.newInstance();
		factoria.setNamespaceAware(true);
		factoria.setValidating(false);
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(fichero);
			SAXParser parser= factoria.newSAXParser();
			parser.parse(fis, this);
		} catch (ParserConfigurationException e) {
			log.error(e);
		} catch (SAXException e) {
			log.error(e);
		} catch (FileNotFoundException e) {
			log.error(e);
		} catch (IOException e) {
			log.error(e);
		} finally {
			if (fis != null) {
				try {
					fis.close();
				} catch (IOException e) {
				}
			}
		}
	}
}