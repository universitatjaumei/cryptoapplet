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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.AccessController;
import java.util.BitSet;

import sun.security.action.GetPropertyAction;

/**
 *  Se tomó como base la clase URLEncoder.java del paquete java.net de SUN Microsystems, Inc.
 *  
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public final class URIEncoder {
    static BitSet dontNeedEncoding;
    static final int caseDiff = ('a' - 'A');
    static String dfltEncName = null;

    static {

	/* The list of characters that are not encoded has been
	 * determined as follows:
	 *
	 * RFC 2396 states:
	 * -----
	 * Data characters that are allowed in a URI but do not have a
	 * reserved purpose are called unreserved.  These include upper
	 * and lower case letters, decimal digits, and a limited set of
	 * punctuation marks and symbols. 
	 *
	 * unreserved  = alphanum | mark
	 *
	 * mark        = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")"
	 *
	 * Unreserved characters can be escaped without changing the
	 * semantics of the URI, but this should not be done unless the
	 * URI is being used in a context that does not allow the
	 * unescaped character to appear.
	 * -----
	 *
	 * It appears that both Netscape and Internet Explorer escape
	 * all special characters from this list with the exception
	 * of "-", "_", ".", "*". While it is not clear why they are
	 * escaping the other characters, perhaps it is safest to
	 * assume that there might be contexts in which the others
	 * are unsafe if not escaped. Therefore, we will use the same
	 * list. It is also noteworthy that this is consistent with
	 * O'Reilly's "HTML: The Definitive Guide" (page 164).
	 *
	 * As a last note, Intenet Explorer does not encode the "@"
	 * character which is clearly not unreserved according to the
	 * RFC. We are being consistent with the RFC in this matter,
	 * as is Netscape.
	 *
	 */

	dontNeedEncoding = new BitSet(256);
	int i;
	for (i = 'a'; i <= 'z'; i++) {
	    dontNeedEncoding.set(i);
	}
	for (i = 'A'; i <= 'Z'; i++) {
	    dontNeedEncoding.set(i);
	}
	for (i = '0'; i <= '9'; i++) {
	    dontNeedEncoding.set(i);
	}
	
	//Caracteres que no hacen falta que sean codificados
	dontNeedEncoding.set('_');
	dontNeedEncoding.set('-');
	dontNeedEncoding.set('!');
	dontNeedEncoding.set('.');
	dontNeedEncoding.set('~');
	dontNeedEncoding.set('\'');
	dontNeedEncoding.set('(');
	dontNeedEncoding.set(')');
	dontNeedEncoding.set('*');
	dontNeedEncoding.set(',');
	dontNeedEncoding.set(';');
	dontNeedEncoding.set(':');
	dontNeedEncoding.set('$');
	dontNeedEncoding.set('&');
	dontNeedEncoding.set('+');
	dontNeedEncoding.set('=');
	dontNeedEncoding.set('?');
	dontNeedEncoding.set('/');
	dontNeedEncoding.set('[');
	dontNeedEncoding.set(']');
	dontNeedEncoding.set('@');
	

    	dfltEncName = (String)AccessController.doPrivileged (
	    new GetPropertyAction("file.encoding")
    	);
    }

    /**
     * You can't call the constructor.
     */
    private URIEncoder() { }

    /**
     * Translates a string into <code>x-www-form-urlencoded</code>
     * format. This method uses the platform's default encoding
     * as the encoding scheme to obtain the bytes for unsafe characters.
     *
     * @param   s   <code>String</code> to be translated.
     * @deprecated The resulting string may vary depending on the platform's
     *             default encoding. Instead, use the encode(String,String)
     *             method to specify the encoding.
     * @return  the translated <code>String</code>.
     */
    @Deprecated
    public static String encode(String s) {

	String str = null;

	try {
	    str = encode(s, dfltEncName);
	} catch (UnsupportedEncodingException e) {
	    // The system should always have the platform default
	}

	return str;
    }

    /**
     * Translates a string into <code>application/x-www-form-urlencoded</code>
     * format using a specific encoding scheme. This method uses the
     * supplied encoding scheme to obtain the bytes for unsafe
     * characters.
     * <p>
     * <em><strong>Note:</strong> The <a href=
     * "http://www.w3.org/TR/html40/appendix/notes.html#non-ascii-chars">
     * World Wide Web Consortium Recommendation</a> states that
     * UTF-8 should be used. Not doing so may introduce
     * incompatibilites.</em>
     *
     * @param   s   <code>String</code> to be translated.
     * @param   enc   The name of a supported 
     *    <a href="../lang/package-summary.html#charenc">character
     *    encoding</a>.
     * @return  the translated <code>String</code>.
     * @exception  UnsupportedEncodingException
     *             If the named encoding is not supported
     * @see URLDecoder#decode(java.lang.String, java.lang.String)
     * @since 1.4
     */
    public static String encode(String s, String enc) 
	throws UnsupportedEncodingException {

	boolean needToChange = false;
	boolean wroteUnencodedChar = false; 
	int maxBytesPerChar = 10; // rather arbitrary limit, but safe for now
        StringBuffer out = new StringBuffer(s.length());
	ByteArrayOutputStream buf = new ByteArrayOutputStream(maxBytesPerChar);

	OutputStreamWriter writer = new OutputStreamWriter(buf, enc);

	for (int i = 0; i < s.length(); i++) {
	    int c = (int) s.charAt(i);
	    //System.out.println("Examining character: " + c);
	    if (dontNeedEncoding.get(c)) {
	
		//System.out.println("Storing: " + c);
		out.append((char)c);
		wroteUnencodedChar = true;
	    } else {
		// convert to external encoding before hex conversion
		try {
		    if (wroteUnencodedChar) { // Fix for 4407610
		    	writer = new OutputStreamWriter(buf, enc);
			wroteUnencodedChar = false;
		    }
		    writer.write(c);
		    /*
		     * If this character represents the start of a Unicode
		     * surrogate pair, then pass in two characters. It's not
		     * clear what should be done if a bytes reserved in the 
		     * surrogate pairs range occurs outside of a legal
		     * surrogate pair. For now, just treat it as if it were 
		     * any other character.
		     */
		    if (c >= 0xD800 && c <= 0xDBFF) {
			/*
			  System.out.println(Integer.toHexString(c) 
			  + " is high surrogate");
			*/
			if ( (i+1) < s.length()) {
			    int d = (int) s.charAt(i+1);
			    /*
			      System.out.println("\tExamining " 
			      + Integer.toHexString(d));
			    */
			    if (d >= 0xDC00 && d <= 0xDFFF) {
				/*
				  System.out.println("\t" 
				  + Integer.toHexString(d) 
				  + " is low surrogate");
				*/
				writer.write(d);
				i++;
			    }
			}
		    }
		    writer.flush();
		} catch(IOException e) {
		    buf.reset();
		    continue;
		}
		byte[] ba = buf.toByteArray();
		for (int j = 0; j < ba.length; j++) {
		    out.append('%');
		    char ch = Character.forDigit((ba[j] >> 4) & 0xF, 16);
		    // converting to use uppercase letter as part of
		    // the hex value if ch is a letter.
		    if (Character.isLetter(ch)) {
			ch -= caseDiff;
		    }
		    out.append(ch);
		    ch = Character.forDigit(ba[j] & 0xF, 16);
		    if (Character.isLetter(ch)) {
			ch -= caseDiff;
		    }
		    out.append(ch);
		}
		buf.reset();
		needToChange = true;
	    }
	}

	return (needToChange? out.toString() : s);
    }
}