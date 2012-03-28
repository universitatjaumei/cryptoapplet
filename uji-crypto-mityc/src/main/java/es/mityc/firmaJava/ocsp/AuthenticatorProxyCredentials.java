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
package es.mityc.firmaJava.ocsp;

import java.net.Authenticator;
import java.net.Authenticator.RequestorType;
import java.net.PasswordAuthentication;

import org.apache.commons.httpclient.NTCredentials;

/**
 * Credenciales de autenticación para conectar el sistema de autenticación de Java con el sistema de credenciales de la librería
 * httpclient.
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class AuthenticatorProxyCredentials extends NTCredentials {
	
	protected PasswordAuthentication pa = null;

	public AuthenticatorProxyCredentials(String host, String domain) {
		super("username", "password", host, domain);
	}
	
	private void refreshAuthenticator() {
        String proxyHost = System.getProperty("http.proxyHost");
    	int proxyPort = 80;
    	try {
    		proxyPort = Integer.parseInt(System.getProperty("http.proxyPort"));
    	} catch (NumberFormatException ex) {
    	}
    	try {
    		pa = Authenticator.requestPasswordAuthentication(proxyHost, null, proxyPort, "HTTP", "", "http", null, RequestorType.PROXY);
    	} catch (SecurityException ex) {
    		pa = null;
    	}
	}
	
	@Override
	public String getUserName() {
		refreshAuthenticator();
    	if (pa == null)
    		return super.getUserName();
		return pa.getUserName();
	}
	
	@Override
	public String getPassword() {
		if (pa == null)
			refreshAuthenticator();
		if (pa == null)
			return super.getPassword();
		return new String(pa.getPassword());
	}

}
