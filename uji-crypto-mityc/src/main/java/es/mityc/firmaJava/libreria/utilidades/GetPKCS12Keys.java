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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.errores.PKCS12Error;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class GetPKCS12Keys implements ConstantesXADES{
	
	static Log log = 
        LogFactory.getLog(GetPKCS12Keys.class);
    
	private String contrasenia =CADENA_VACIA;
    private String fichero =CADENA_VACIA;
    private KeyStore ks = null;
    private String claveAlias = null;
    private Configuracion configuracion = new Configuracion();
    
    /** Crea una nueva instancia de GetPKCS12Keys
     *  @param fichero
     *  @param contraseña
     */
    public GetPKCS12Keys(String fichero, String contrasenia) throws PKCS12Error {
    	InputStream fis = null;
        try{
    		//Carga la configuración
    		configuracion.cargarConfiguracion();
        	//Establece el idioma según la configuración
    		String locale = configuracion.getValor(LOCALE);
            // Configura el idioma
            I18n.setLocale(locale, locale.toUpperCase());
            if(contrasenia == null ){
            	throw new PKCS12Error(I18n.getResource(LIBRERIAXADES_GETPKCS12KEYS_TEXTO_1));
            }
            if (fichero == null || fichero.trim().equals(CADENA_VACIA)){
            	throw new PKCS12Error(I18n.getResource(LIBRERIAXADES_GETPKCS12KEYS_TEXTO_2));
            }

            	this.contrasenia = contrasenia ;
            	this.fichero = fichero ;
            	ks = KeyStore.getInstance(PKCS12);
            	fis = new FileInputStream(fichero);
            	ks.load(fis, contrasenia.toCharArray());
            	Enumeration e = ks.aliases();

            	while (e.hasMoreElements())
            	{
                	String alias = (String)e.nextElement();
                	if (ks.isKeyEntry(alias))
                	{
                    	claveAlias = alias;
                    	break ;
                	}
            	}
            	if (claveAlias==null){
            		throw new PKCS12Error(I18n.getResource(LIBRERIAXADES_GETPKCS12KEYS_TEXTO_3));
            	}
            
        } catch (KeyStoreException e){
        	throw new PKCS12Error(e.getMessage());
        } catch (FileNotFoundException e) {
        	throw new PKCS12Error(e.getMessage());	
        } catch (NoSuchAlgorithmException e) {
        	throw new PKCS12Error(e.getMessage());
		} catch (CertificateException e) {
        	throw new PKCS12Error(e.getMessage());
		} catch (IOException e) {
        	throw new PKCS12Error(e.getMessage());
		}
        
        finally {
        	
        	if (fis != null){
        		try {
					fis.close();
				} catch (IOException e) {
					log.error(e);
				}
        	}
        	
        }
    }
    
    /**
     * Obtiene la clave privada
     * @return Devuelve la clave privada
     * @throws PKCS12Error
     */
    public PrivateKey getPrivateKey() throws PKCS12Error {
        try{
            // Leer certificado
            PrivateKey clavePrivada = (PrivateKey) ks.getKey(claveAlias,
                contrasenia.toCharArray());
            return clavePrivada ;
        }catch (Exception e){
            throw new PKCS12Error(e);
        }
    }
    
    /**
     * Obtiene el certificado
     * @return Devuelve el certificado
     * @throws PKCS12Error
     */
    public X509Certificate getCertificate() throws PKCS12Error {
        try{
            X509Certificate cert = (X509Certificate) ks.getCertificate(claveAlias);
            return cert;
        }catch (Exception e){
            throw new PKCS12Error(e);
        }
    }
    
    /**
     * Obtiene la contraseña.
     * @return Valor de la contraseña. 
     */
    public String getPassword() {
        return contrasenia;
    }
     
    /**
     * Obtiene el fichero.
     * @return Valor del fichero.
     */
    public String getFile() {
        return fichero;
    }
    
    /**
     * Obtiene la claveAlias
     * @return Valor de la claveAlias.
     */
    public String getKeyAlias() {
        return claveAlias;
    }
}

