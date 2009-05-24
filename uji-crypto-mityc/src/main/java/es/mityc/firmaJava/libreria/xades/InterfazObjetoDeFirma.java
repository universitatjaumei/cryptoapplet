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
package es.mityc.firmaJava.libreria.xades;

import java.io.File;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;

import es.mityc.firmaJava.libreria.errores.ClienteError;

/**
 * Interfaz para los objetos de firma
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public interface InterfazObjetoDeFirma {

	/**
     * Obtiene el certificado firmante
     * @return Certificado firmado
     */
    X509Certificate getSignCertificate();

    /**
     * Inicializa el proceso de firma
     * @throws ClienteError En caso de error
     */
    void initSign() throws ClienteError;

    /**
     * Realiza la firma digital
     * @param xmlNoSign Documento XML a firmar
     * @return File fichero temporal con la firma
     * @throwsClienteErrorKit.exceptions.ClientException En caso de error
     */
    boolean sign(File xmlNoSign, String destino, String nombreArchivo) throws ClienteError;
    
    /**
     * Realiza la firma digital
     * 
     * @param doc Documento que hay que firmar
     * @return Document firmado
     * @throws ClienteError
     */
    Document sign(Document doc) throws ClienteError;
    
    /**
     * Realiza la firma digital
     * @param xmlNoSign Documento XML a firmar
     * @return byte[] fichero de bytes con la firma
     * @throwsClienteErrorKit.exceptions.ClientException En caso de error
     */
    byte[] sign(String xmlNoFirmado) throws ClienteError;
    
}
