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

/**
 * Convierte Array de bytes a Hexadecimal
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ByteArrayAHex
{
	
	
	final private static char[] NIBBLE = {
                                      '0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                                  };

    /**
     * Devuelve la cadena en Hexadecimal
     * @param buf 
     * @param i 
     * @param longitud 
     * @return 
     */
	public static final String hexString(byte[] buf, int i, int longitud)
    {
    StringBuffer sb = new StringBuffer();
        for (int j=i; j<i+longitud ; j++) {
           sb.append(NIBBLE[(buf[j]>>>4)&15]);
           sb.append(NIBBLE[ buf[j]     &15]);
        }
        return String.valueOf(sb);
    }

    /**
     * Devuelve la cadena en hexadecimal
     * @param buf 
     * @return 
     */
    public static final String hexString(byte[] buf)
    {
        return hexString(buf, 0, buf.length);
    }

    /**
     * 
     * @param n 
     * @return 
     */
     public static byte fromHexNibble(char n)
    {
        if(n<='9')
            return (byte)(n-'0');
        if(n<='G')
            return (byte)(n-('A'-10));
        return (byte)(n-('a'-10));
    }

    /**
     * Convierte una cadena de digitos hexadecimales a un array de bytes
     * @param hex
     */
    public static byte[] fromHexString(String hex)
    {
        int l=(hex.length()+1) >>> 1;
        byte[] r = new byte[l];
        int i = 0;
        int j = 0;
        if(hex.length()%2 != 0) {
            // Número impar de caracteres: debe manejar medio byte primero. 
            r[0]=fromHexNibble(hex.charAt(0));
            i=j=1;
        }
        while(i<l)
            r[i++] = (byte)((fromHexNibble(hex.charAt(j++)) << 4) | fromHexNibble(hex.charAt(j++)));
        return r;
    }
    
    /**
     * Concatena 2 arrays de bytes
     */
    public static byte[] concatByteArrays(byte[] array1, byte[] array2) {
    	
    	if(array1.length == 0)
    		return array2;
    	else if(array2.length == 0)
    		return array1;
    	else
    	{
    		int logitudFinal = array1.length + array2.length;
    		byte[] arrayCombinado = new byte[logitudFinal];
    		// añadir primer array
//    		for(int i=0; i<array1.length; i++)
//    		{
//    			System.arraycopy(arrayCombinado, 0, array1, 0, array1.length);
    		System.arraycopy(array1,0, arrayCombinado, 0, array1.length);
//    			arrayCombinado[i] = array1[i];
//    		}
    		// añadir segundo array
//    		int b = 0;
//    		for(int i=array1.length; i<logitudFinal; i++)
//    		{
//    			arrayCombinado[i] = array2[b];
//    			b++;
//    		}
//    		System.arraycopy(arrayCombinado, array1.length, array2, 0, logitudFinal);
    		System.arraycopy(array2, 0, arrayCombinado, array1.length, array2.length);
    		
    		return arrayCombinado;
    	}
    }
}