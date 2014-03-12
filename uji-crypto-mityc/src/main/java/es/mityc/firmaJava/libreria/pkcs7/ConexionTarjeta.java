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

package es.mityc.firmaJava.libreria.pkcs7;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.cert.CertificateException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import sun.security.pkcs11.SunPKCS11;
import sun.security.pkcs11.wrapper.PKCS11Exception;
import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class ConexionTarjeta implements ConstantesXADES{

	private static ConexionTarjeta conexion	= null;
		
	private ConexionTarjeta()
	{
		// Creates the one and only instance of the class
	}
	
	public static ConexionTarjeta getInstance()
	{
		if(conexion == null)
		{
			conexion = new ConexionTarjeta();
		}
		return conexion;
	}
	
	
	/**
	 * @param args
	 */
	public static KeyStore conectar(char[] pin, String libreria)
		throws PKCS11Exception, ProviderException
	{
		KeyStore ks = null;
		try
		{									
			if (Security.getProvider(SUNPCKS11_TOKEN)!=null)
				Security.removeProvider(SUNPCKS11_TOKEN);
			String pkcs11config =
				NAME_IGUAL_TOKEN +
			   LIBRARY_IGUAL + libreria;
			byte[] pkcs11configBytes = pkcs11config.getBytes();
			ByteArrayInputStream configStream =
			   new ByteArrayInputStream(pkcs11configBytes);
			Provider pkcs11Provider = new SunPKCS11(configStream);
			Security.addProvider(new BouncyCastleProvider());
			Security.addProvider(pkcs11Provider);
			
			ks = KeyStore.getInstance(PKCS11, pkcs11Provider);
			ks.load(null, pin);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			Throwable t = null;
			if(e.getCause() != null)
			{
				t = e.getCause();
			
					if(t.getCause() != null && t.getCause() instanceof PKCS11Exception)
					{
						PKCS11Exception pke = (PKCS11Exception) t.getCause();
						throw new PKCS11Exception(pke.getErrorCode());
					}
				
			}
		} catch (KeyStoreException e) {
			throw new PKCS11Exception(-1);
		} catch(ProviderException e) {
			if(e.getCause() != null)
			{
				Throwable t = e.getCause();
				if(t instanceof PKCS11Exception)
				{
					PKCS11Exception pke = (PKCS11Exception) t;
					throw new PKCS11Exception(pke.getErrorCode());
				}
				else
					throw e;
			}
			else
			{
				throw new ProviderException(e.getMessage());
			}
		} catch(Throwable t) {
			t.printStackTrace();
		}
		return ks;
	}	
}