package es.mityc.firmaJava.libreria.utilidades;

import java.net.Authenticator;
import java.net.PasswordAuthentication;

/**
 * Authenticator que devuelve el usuario y contraseña configurados en cualquier circunstancia.
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class SimpleAuthenticator extends Authenticator {
	
	private transient String username;
	private transient String password; 

	public SimpleAuthenticator(String username, String password) {
		super();
		this.username = username;
		this.password = password;
	}
	
	@Override
	protected PasswordAuthentication getPasswordAuthentication() {
		return new PasswordAuthentication(username, password.toCharArray());
	}

}
