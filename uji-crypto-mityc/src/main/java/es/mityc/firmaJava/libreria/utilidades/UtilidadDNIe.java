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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Vector;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

import es.mityc.firmaJava.libreria.ConstantesXADES;

/**
 * Clase de utilidades para el DNIe
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class UtilidadDNIe implements ConstantesXADES {
	
	static Log log = LogFactory.getLog(UtilidadDNIe.class);

	public enum SUBJECT_OR_ISSUER {
		SUBJECT, 
		ISSUER
	};
	
    /**
     * Constructor por defecto de la clase
     */
    public UtilidadDNIe() {        
    }
    
    /**
     * Obtiene el nombre común
     * 
     * @param cert X509Certificate Certificado del cual se obtiene el nombre
     * @param tipo Tipo de certificado
     * @return String CN obtenido 
     */
    public static String getCN(X509Certificate cert, SUBJECT_OR_ISSUER tipo){
    	
    	String retorno = CADENA_VACIA;
    	X509Principal nombre = null;
    	
    	// Se discrimina que tipo de certificado es requerido
    	try {
    		if (tipo == SUBJECT_OR_ISSUER.ISSUER)
    			nombre = PrincipalUtil.getIssuerX509Principal(cert);
    		else
    			nombre = PrincipalUtil.getSubjectX509Principal(cert);
    	
    	} catch (CertificateEncodingException e) {
			log.error(e.getMessage(), e);
			return retorno;
		}
    	
    	// Se obtienen sus valores asociados
    	Vector commonNameOIDs = nombre.getOIDs();
    	Vector commonName = nombre.getValues();
		int longitudValues = commonName.size();
    	
		if (longitudValues != 0) {
			// Se busca el valor "CN"
			int indexCN = commonNameOIDs.indexOf(X509Name.CN);
			if (indexCN != -1) {
				Object elemento = commonName.get(indexCN);
				if (elemento instanceof String)
					retorno = (String) elemento;
				else
					log.error(ERR_CN_NO_TIPO_STRING);
			}

			// Si no se obtuvo resultado, se busca el valor "OU"
			if (retorno == CADENA_VACIA) {
				int indexOU = commonNameOIDs.indexOf(X509Name.OU);
				if (indexOU != -1) {
					Object elemento = commonName.get(indexOU);
					if (elemento instanceof String)
						retorno = (String) elemento;
					else
						log.error(ERR_CN_NO_TIPO_STRING);
				}
			}

			// Si no se obtuvo resultado, se busca el valor "O"
			if (retorno == CADENA_VACIA || retorno == null) {
				int indexO = commonNameOIDs.indexOf(X509Name.O);
				if (indexO != -1) {
					Object elemento = commonName.get(indexO);
					if (elemento instanceof String)
						retorno = (String) elemento;
					else
						log.error(ERR_CN_NO_TIPO_STRING);
				}
			}
		} else
			log.error(ERR_CERT_NO_VALUES);

		return retorno;
    }

    /**
     * Convierte un java.util.Date a DateFormat.SHORT,new Locale("ES","es")
     * @param date Fecha a convertir
     * @return String en formato DateFormat.SHORT,new Locale("ES","es")
     */
    public static String convertDate(Date date){
        DateFormat formatoFecha = DateFormat.getDateInstance(DateFormat.SHORT, new Locale(ES_MAYUSCULA,ES_MINUSCULA)) ;
        return formatoFecha.format(date);
    }

    /**
     * Obtiene el numero de DNI del Subject del certificado
     * @param subjectDN Subject del certificado
     * @return Numero del DNI
     */
    public static final String giveMeDNINumber(String subjectDN){
        if (subjectDN == null){
            return null;
        }
        String[] tokens = subjectDN.split(COMA);
        
        for (int a=0;a<tokens.length;a++){
        	String[] nDNI = null;

            if(tokens[a].trim().startsWith(NUMERO_DE_SERIE)){
                nDNI= tokens[a].trim().split(IGUAL);
                return nDNI[1].trim();
            }else if(tokens[a].trim().startsWith(OID_2_5_4_5)){
                nDNI= tokens[a].trim().split(IGUAL);
                return nDNI[1].trim();
            }else if(tokens[a].trim().startsWith(SERIAL_NUMBER)){
                nDNI= tokens[a].trim().split(IGUAL);
                return nDNI[1].trim();
            }
        }
        return null;
    }
    
    /**
     * Comprueba si es un certificado de DNIe
     * @param emisorDN Emisor del certificado
     * @return Verdadero si lo es, Falso en caso contrario
     */
    public static final boolean isCertDNIe(String emisorDN){
        return emisorDN.indexOf(OU_DNIE)>=0 && 
        emisorDN.indexOf(O_DIRECCION_GENERAL_DE_LA_POLICIA)>=0 ;
    }

}
