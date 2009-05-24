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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Conjunto de utilidades para el tratamiento genérico de certificados.
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class UtilidadCertificados {
	
	private static final Log logger = LogFactory.getLog(UtilidadCertificados.class);
	
	public enum Filter { SIGN_SIGNER, CRL_SIGNER, OCSP_SIGNER, TS_SIGNER}; 
	private final static String OID_OCSP_SIGNING	= "1.3.6.1.5.5.7.3.9"; 
	private final static String OID_TS_SIGNING 		= "1.3.6.1.5.5.7.3.8";

	/**
     * Recupera los CertPath's de certificados que pueda encontrar en el listado de certificados provistos.
     * 
     * @param certificates Listado de certificados
     * @return ArrayList con los CertPath's que se han podido construir
     */
    public static ArrayList<CertPath> getCertPaths(Iterable<X509Certificate> certificates) {
    	ArrayList<ArrayList<X509Certificate>> list = getCertPathsArray(certificates);
    	ArrayList<CertPath> certPaths = new ArrayList<CertPath>();
    	Iterator<ArrayList<X509Certificate>> itArrays = list.iterator();
    	while (itArrays.hasNext()) {
			CertPath cp = convertCertPath(itArrays.next());
			if (cp != null)
				certPaths.add(cp);
    	}
    	return certPaths;
    }
    
	/**
     * Recupera los CertPath's de certificados que pueda encontrar en el listado de certificados provistos.
     * 
     * @param certificates Listado de certificados
     * @return ArrayList con los CertPath's que se han podido construir
     */
    public static ArrayList<ArrayList<X509Certificate>> getCertPathsArray(Iterable<X509Certificate> certificates) {
    	ArrayList<ArrayList<X509Certificate>> certPaths = new ArrayList<ArrayList<X509Certificate>>();
    	if (certificates != null) {
    		// Pasa todos los certificados a una lista enlazada eliminando los certificados repetidos
    		ArrayList<NTo1Link<X509Certificate>> list = new ArrayList<NTo1Link<X509Certificate>>();
    		Iterator<X509Certificate> itCerts = certificates.iterator();
    		while (itCerts.hasNext()) {
    			NTo1Link<X509Certificate> nodo = new NTo1Link<X509Certificate>(itCerts.next());
    			if (!list.contains(nodo))
    				list.add(nodo);
    		}
    		// Busca para cada certificado su relación (hijo de, padre de)
    		for (int i = 0; i < list.size(); i++) {
    			for (int j = i + 1; j < list.size(); j++) {
    				linkCerts(list.get(i), list.get(j));
    			}
    		}
    		// Busca los nodos que no tengan previos. Esos son los comienzos de una cadena
    		Iterator<NTo1Link<X509Certificate>> itNodos = list.iterator();
    		while (itNodos.hasNext()) {
    			NTo1Link<X509Certificate> nodo = itNodos.next();
    			if (nodo.getNumPrevs() == 0) {
    				ArrayList<X509Certificate> cp = convertCertPathArray(nodo);
    				if (cp != null)
    					certPaths.add(cp);
    			}
    		}
    	}
    	return certPaths;
    }
    
    public static ArrayList<ArrayList<X509Certificate>> filterCertPathsArrays(ArrayList<ArrayList<X509Certificate>> list, Filter filter) {
    	ArrayList<ArrayList<X509Certificate>> result = new ArrayList<ArrayList<X509Certificate>>();
    	Iterator<ArrayList<X509Certificate>> it = list.iterator();
    	while (it.hasNext()) {
    		ArrayList<X509Certificate> certs = it.next();
    		if ((certs != null) && (certs.size() > 0)) {
    			if (Filter.OCSP_SIGNER.equals(filter)) {
    				if (isOCSPSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.TS_SIGNER.equals(filter)) {
    				if (isTSSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.CRL_SIGNER.equals(filter)) {
    				if (isCRLSigning(certs.get(0)))
    	        		result.add(certs);
    			}
    			else if (Filter.SIGN_SIGNER.equals(filter)) {
    				if ((!isOCSPSigning(certs.get(0))) && (!isTSSigning(certs.get(0))))
    	        		result.add(certs);
    			}
    		}
    	}
    	return result;
    }
    
    private static boolean isOCSPSigning(X509Certificate cert) {
    	try {
			List<String> list = cert.getExtendedKeyUsage();
			if (list != null) {
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					if (OID_OCSP_SIGNING.equals(it.next()))
						return true;
				}
			}
		} catch (CertificateParsingException ex) {
		}
    	return false;
    }

    private static boolean isTSSigning(X509Certificate cert) {
    	try {
			List<String> list = cert.getExtendedKeyUsage();
			if (list != null) {
				Iterator<String> it = list.iterator();
				while (it.hasNext()) {
					if (OID_TS_SIGNING.equals(it.next()))
						return true;
				}
			}
		} catch (CertificateParsingException ex) {
		}
    	return false;
    }

    private static boolean isCRLSigning(X509Certificate cert) {
		boolean[] usage = cert.getKeyUsage();
		if ((cert != null) && (usage[6]))
			return true;
		return false;
    }

    /**
     * Relaciona los certificados indicados entre si (si existe alguna relación)
     * @param nodo1
     * @param nodo2
     * 
     * TODOLARGO: permitir establecer políticas de severidad a la hora de buscar las relaciones entre los certificados. Estas
     * políticas pueden ser por ejemplo que se compruebe que un certificado ha firmado al otro, que campos opcionales sean
     * exigidos como presentes, que alguno de los certificados de las cadenas resultantes sean certificados de confianza, etc.
     */
    private static void linkCerts(NTo1Link<X509Certificate> nodo1, NTo1Link<X509Certificate> nodo2) {
    	if (nodo1.getData().getIssuerX500Principal().equals(nodo2.getData().getSubjectX500Principal())) {
    		// Comprueba que el certificado padre generó al certificado hijo
    		try {
				nodo1.getData().verify(nodo2.getData().getPublicKey());
			} catch (InvalidKeyException ex) {
				return;
			} catch (CertificateException ex) {
				return;
			} catch (NoSuchAlgorithmException ex) {
				return;
			} catch (NoSuchProviderException ex) {
				return;
			} catch (SignatureException ex) {
				return;
			}
    		
    		nodo1.setNext(nodo2);
    		nodo2.addPrev(nodo1);
    	} else if (nodo2.getData().getIssuerX500Principal().equals(nodo1.getData().getSubjectX500Principal())) {
    		// Comprueba que el certificado padre generó al certificado hijo
    		try {
				nodo2.getData().verify(nodo1.getData().getPublicKey());
			} catch (InvalidKeyException ex) {
				return;
			} catch (CertificateException ex) {
				return;
			} catch (NoSuchAlgorithmException ex) {
				return;
			} catch (NoSuchProviderException ex) {
				return;
			} catch (SignatureException ex) {
				return;
			}

    		nodo2.setNext(nodo1);
    		nodo1.addPrev(nodo2);
    	}
    }
    
    /**
     * Convierte una sucesion de nodos enlazados en un CertPath
     * @param nodo
     * @return
     */
    public static CertPath convertCertPath(ArrayList<X509Certificate> certs) {
    	CertPath cp = null;
    	try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			cp = cf.generateCertPath(certs);
		} catch (CertificateException ex) {
			logger.error("Error al intentar generar CertPaths", ex);
		}
    	return cp;
    }
    
    /**
     * Convierte una sucesion de nodos enlazados en un CertPath
     * @param nodo
     * @return
     */
    private static ArrayList<X509Certificate> convertCertPathArray(NTo1Link<X509Certificate> nodo) {
    	ArrayList<X509Certificate> certs = new ArrayList<X509Certificate>();
    	Iterator<NTo1Link<X509Certificate>> itNodo = nodo.iterator();
    	while (itNodo.hasNext()) {
    		certs.add(itNodo.next().getData());
    	}
    	return certs;
    }
}
