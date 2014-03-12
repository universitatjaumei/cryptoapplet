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

package es.mityc.firmaJava.ts;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.tsp.TSPAlgorithms;

/**
 * Clase con los algortimos de codificacion permitidos
 * para el sellado de tiempo
 * 
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class TSPAlgoritmos implements ConstantesTSA{
	
	public static Set getPermitidos(){
		
		Set permitidos = new HashSet(Arrays.asList(getValoresPermitidos()));
		
		return permitidos;
		
	}
	
	public static String getAlgName(String oid) {
		if (TSPAlgorithms.SHA1.equals(oid))
			return SHA1;
		else if (TSPAlgorithms.SHA256.equals(oid))
			return SHA2;
		else if (TSPAlgorithms.SHA224.equals(oid))
			return SHA224;
		else if (TSPAlgorithms.SHA256.equals(oid))
			return SHA256;
		else if (TSPAlgorithms.SHA384.equals(oid))
			return SHA384;
		else if (TSPAlgorithms.SHA512.equals(oid))
			return SHA512;
		return oid;
	}
	

	public static String getOID(String algoritmo) {

		Set permitidos = new HashSet(Arrays.asList(getValoresPermitidos()));
		
		if (permitidos.contains(algoritmo)) {
			if (SHA1.equals(algoritmo))
				return TSPAlgorithms.SHA1;
			else if (SHA2.equals(algoritmo))
				return TSPAlgorithms.SHA256;
			else if (SHA224.equals(algoritmo))
				return TSPAlgorithms.SHA224;
			else if (SHA256.equals(algoritmo))
				return TSPAlgorithms.SHA256;
			else if (SHA384.equals(algoritmo))
				return TSPAlgorithms.SHA384;
			else if (SHA512.equals(algoritmo))
				return TSPAlgorithms.SHA512;
		}
		return null;
	}
	
	public static HashMap<String, String> algoritmosVSoids = null;
	static {
		algoritmosVSoids = new HashMap<String, String>();
		
		algoritmosVSoids.put(TSPAlgorithms.SHA1, SHA1); // SHA-1
		algoritmosVSoids.put(TSPAlgorithms.SHA224,SHA224);
		algoritmosVSoids.put(TSPAlgorithms.SHA256,SHA256); // SHA-256
		algoritmosVSoids.put(TSPAlgorithms.SHA384,SHA384);
		algoritmosVSoids.put(TSPAlgorithms.SHA512,SHA512);
		algoritmosVSoids.put(TSPAlgorithms.MD5,MD5); //md5
		
	}
	
	/**
	 * Devuelve el algoritmo de digest asociado con el OID de algoritmo de digest indicado.
	 * 
	 * @param oid Cadena de texto con el OID del algoritmo
	 * @return MessageDigest del OID indicado, <code>null<code> si no se dispone de un
	 * 		   algoritmo de digest asociado al OID indicado.
	 */
	public static MessageDigest getDigest(String oid) {
		String algName = algoritmosVSoids.get(oid);
		if (algName == null)
			return null;
		try {
			MessageDigest md = MessageDigest.getInstance(algName);
			return md;
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}
	
 
	public	static String[] getValoresPermitidos(){
		String[] valoresPermitidos = new String[6];
		valoresPermitidos[0] = SHA1;
		valoresPermitidos[1] = SHA2;
		valoresPermitidos[2] = SHA224;
		valoresPermitidos[3] = SHA256;
		valoresPermitidos[4] = SHA384;
		valoresPermitidos[5] = SHA512;
		return valoresPermitidos;
		
	}
	
}


