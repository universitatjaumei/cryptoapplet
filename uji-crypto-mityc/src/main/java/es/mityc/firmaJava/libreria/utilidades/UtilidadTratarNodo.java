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
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class UtilidadTratarNodo implements ConstantesXADES {
	
	static Log log = LogFactory.getLog(UtilidadTratarNodo.class);
	
	private final static String[] IDs = {ID, ID_MINUS, ID_MAYUS}; 

	private static Random rnd = new Random(new Date().getTime());
	private final static int RND_MAX_SIZE = 1048576;

	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del documento, y que se ajusten al namespace.
	 * 
	 * @param doc documento en el que se buscarán los hijos (en cualquier profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo raiz)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Document doc, String ns, String nombreHijos) throws FirmaXMLError{
		return obtenerByteNodo(doc.getDocumentElement(), ns, nombreHijos);
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * Equivalente a la ejecución:
	 * <blockquote>
	 * obtenerByteNodo(Element padre, String ns, String nombreHijos, true)
	 * </blockquote>
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (en cualquier profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos) throws FirmaXMLError{
		return obtenerByteNodo(padre, ns, nombreHijos, true);
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (en cualquier profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @param requerido Si el valor es <code>true</code> y no se encuentra ningún hijo lanzará excepción
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos, boolean requerido) throws FirmaXMLError{
    	NodeList nodesHijos = null;
    	
		if (ns == null)
			ns = padre.getNamespaceURI();
		
		nodesHijos = padre.getElementsByTagNameNS(ns, nombreHijos);
    	log.debug(MSG_NUMERO_FIRMAS_DOCUMENTO +  nodesHijos.getLength());
    	    	
    	if ((nodesHijos.getLength() == 0) && (requerido)) {
        	log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8) + ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO + nombreHijos);
        	throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8) + ESPACIO +  I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_33) + ESPACIO + nombreHijos);
        }  

    	if (nodesHijos.getLength() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.getLength(); i++) {
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodesHijos.item(i));
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param ns namespace en el que deben estar los hijos que se van a buscar (<code>null</code> si el mismo namespace que el nodo padre)
	 * @param nombreHijos nombre del tag de los hijos que se buscarán
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el array de bytes), <code>null</code> si no se quiere tope
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, String ns, String nombreHijos, Element tope) throws FirmaXMLError {
    	NodeList nodesHijos = null;
    	
		if (ns == null)
			ns = padre.getNamespaceURI();
		
		nodesHijos = padre.getChildNodes();
    	    	
    	if (nodesHijos.getLength() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.getLength(); i++) {
				Node nodo = nodesHijos.item(i);
				
				// Busca el siguiente elemento
				if (nodo.getNodeType() != Node.ELEMENT_NODE)
					continue;
				
				// si es el elemento tope para de buscar
				if (tope != null) {
					if (tope.isEqualNode(nodo))
						break;
				}
				
				// comprueba si es un nodo de los buscados
				if (!nodo.getLocalName().equals(nombreHijos))
					continue;
				
				if (ns == null) {
					if (nodo.getNamespaceURI() != null)
						continue;
				} else if (!ns.equals(nodo.getNamespaceURI()))
					continue;
				
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}
	
	/**
	 * Devuelve en un array de bytes el contenido de los nodos indicados que sean hijos del nodo padre, y que se ajusten al namespace.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param nombreHijos listado de elementos que se buscarán (pareja de namespace y nombre del elemento)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el array de bytes), <code>null</code> si no se quiere tope
	 * @return byte array con el contenido de los nodos hijos, <code>null</code> si no tiene hijos y no es requerido
	 * @throws FirmaXMLError 
	 */
	public static byte[] obtenerByteNodo(Element padre, ArrayList<NombreNodo> nombreHijos, Element tope) throws FirmaXMLError {
    	NodeList nodesHijos = null;
    	
		nodesHijos = padre.getChildNodes();
    	    	
    	if (nodesHijos.getLength() > 0) { 
        	Transforms  t = new Transforms(padre.getOwnerDocument());
        	
        	try {
    			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    		} catch (TransformationException e) {
    			log.error(e);
    			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
    		}
    		
			ByteArrayOutputStream bais = new ByteArrayOutputStream();
			
			for (int i = 0; i < nodesHijos.getLength(); i++) {
				Node nodo = nodesHijos.item(i);
				
				// Busca el siguiente elemento
				if (nodo.getNodeType() != Node.ELEMENT_NODE)
					continue;
				
				// si es el elemento tope para de buscar
				if (tope != null) {
					if (tope.isEqualNode(nodo))
						break;
				}
				
				// comprueba si es un nodo de los buscados
				NombreNodo nombreNodo = new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName());
				if (nombreHijos.indexOf(nombreNodo) == -1)
					continue;
				
				XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
				try {
					XMLSignatureInput resultado = null;
					resultado = t.performTransforms(xmlSignatureInput);
					bais.write(resultado.getBytes());
				} catch (TransformationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (CanonicalizationException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				} catch (IOException ex) {
					log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
					throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
				}
			}
			
			if (bais.size() > 0) 
				return bais.toByteArray();
	    }
		return null;
	}

	/**
	 * Devuelve un listado con los elementos que siendo hijos del nodo padre tienen el nombre indicado y están antes del elemento tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el listado), <code>null</code> si no se quiere tope
	 * @param nombreHijo Namespace y localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 */
	public static ArrayList<Element> obtenerNodos(Element padre, Element tope, NombreNodo nombreHijo) {
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
		for (int i = 0; i < nodesHijos.getLength(); i++) {
			Node nodo = nodesHijos.item(i);
			
			// Busca el siguiente elemento
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				continue;
			
			// si es el elemento tope para de buscar
			if (tope != null) {
				if (tope.isEqualNode(nodo))
					break;
			}
			
			// comprueba si es un nodo de los buscados
			if (new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName()).equals(nombreHijo))
				resultado.add((Element)nodo);
		}
		return resultado;
	}
	
	/**
	 * Devuelve un listado con los elementos que siendo hijos del nodo padre tienen el nombre indicado y están antes del elemento tope.
	 * 
	 * @param padre nodo padre del que se buscarán los hijos (sólo en un nivel de profundidad)
	 * @param tope Elemento en el que se para la búsqueda (no se incluirá en el listado), <code>null</code> si no se quiere tope
	 * @param nombreHijos listado de Namespace y localname de los hijos que se buscarán
	 * @return listado con los elementos encontrados
	 * @throws FirmaXMLError 
	 */
	public static ArrayList<Element> obtenerNodos(Element padre, Element tope, ArrayList<NombreNodo> nombreHijos) throws FirmaXMLError {
		ArrayList<Element> resultado = new ArrayList<Element>();
    	NodeList nodesHijos = padre.getChildNodes();
    	
		for (int i = 0; i < nodesHijos.getLength(); i++) {
			Node nodo = nodesHijos.item(i);
			
			// Busca el siguiente elemento
			if (nodo.getNodeType() != Node.ELEMENT_NODE)
				continue;
			
			// si es el elemento tope para de buscar
			if (tope != null) {
				if (tope.isEqualNode(nodo))
					break;
			}
			
			// comprueba si es un nodo de los buscados
			if (nombreHijos.indexOf(new NombreNodo(nodo.getNamespaceURI(), nodo.getLocalName())) != -1)
				resultado.add((Element)nodo);
		}
		return resultado;
	}
	
	/**
	 * Devuelve un array de bytes con el contenido de los elementos indicados (tras una canonalización estándar).
	 * 
	 * @param nodos listado de elementos
	 * @return array de bytes 
	 */
	public static byte[] obtenerByte(ArrayList<Element> nodos) throws FirmaXMLError {
		if ((nodos == null) || (nodos.size() == 0))
			return null;
		
    	Transforms  t = new Transforms(nodos.get(0).getOwnerDocument());
    	
    	try {
			t.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
		} catch (TransformationException e) {
			log.error(e);
			throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
		}
		
		ByteArrayOutputStream bais = new ByteArrayOutputStream();
		
		Iterator<Element> it = nodos.iterator();
		while (it.hasNext()) {
			Element nodo = it.next();
			
			XMLSignatureInput xmlSignatureInput = new XMLSignatureInput(nodo);
			try {
				XMLSignatureInput resultado = null;
				resultado = t.performTransforms(xmlSignatureInput);
				bais.write(resultado.getBytes());
			} catch (TransformationException ex) {
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
			} catch (CanonicalizationException ex) {
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
			} catch (IOException ex) {
				log.error(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_34), ex);
				throw new FirmaXMLError(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_8));
			}
		}
		
		if (bais.size() > 0) 
			return bais.toByteArray();
		return null;
	}
	
	/**
	 * Devuelve un listado con las ID de los elementos. Si no encuentra un atributo que sea ID, busca entre los atributos alguno que tenga
	 * la <i>forma</i> de ID.
	 * 
	 * @param elementos listado con los elementos de los cuales obtener las IDs
	 * @return
	 */
	public static ArrayList<String> obtenerIDs(ArrayList<Element> elementos) {
		if (elementos == null)
			return null;
		ArrayList<String> resultado = new ArrayList<String>();
		Iterator<Element> it = elementos.iterator();
		while (it.hasNext()) {
			Element elemento = it.next();
			boolean encontrado = false;
			NamedNodeMap map = elemento.getAttributes();
			for (int i = 0; i < map.getLength(); i++) {
				Attr attr = (Attr)map.item(i);
				if (attr.isId()) {
					resultado.add(attr.getValue());
					encontrado = true;
					break;
				}
			}
			if (!encontrado) {
				for (int i = 0; i < IDs.length; i++) {
					if (elemento.hasAttribute(IDs[i])) {
						resultado.add(elemento.getAttribute(IDs[i]));
						break;
					}
				}
			}
		}
		return resultado;
	}

	/**
	 * Busca en una lista de nodos un elemento que tenga la id indicada
	 *  
	 * @param id
	 * @return
	 */
	public static Element getElementById(NodeList list, String id) {
		Element resultado = null;
		if (list != null) {
			int length = list.getLength();
			for (int i = 0; i < length; i++) {
				Node node = list.item(i);
				// AppPerfect: Falso positivo
				if (node.getNodeType() == Node.ELEMENT_NODE) {
					Element el = (Element) node;
					if (id.equals(el.getAttribute(ID))) {
						resultado = el;
						break;
					}
				}
			}
		}
		return resultado;
	}
	
	/**
	 * Explora el elemento y sus hijos para obtener un elemento que tenga la Id indicada
	 * 
	 * @param el
	 * @param id
	 * @return
	 */
	private static Element exploreElementById(Element el, String id) {
		for (int i = 0; i < IDs.length; i++) {
			if (id.equals(el.getAttribute(IDs[i]))) {
				return el; 
			}
		}
		// explora los hijos del nodo
		NodeList nodes = el.getChildNodes();
		for (int i = 0; i < nodes.getLength(); i++) {
			Node nodo = nodes.item(i);
			if (nodo.getNodeType() == Node.ELEMENT_NODE) {
				Element temp = exploreElementById((Element)nodo, id);
				if (temp != null)
					return temp;
			}
		}
		return null;
	}
	
	/**
	 * Busca un nodo que tenga la Id indicada. Busca la id en cualquier atributo que tenga la forma Id, ID, ó id.
	 * 
	 * @param doc
	 * @param id
	 * @return el elemento con la id indicada, <code>null</code> si no hay ningún elemento con esa id.
	 */
	public static Element getElementById(Document doc, String id) {
		if ((doc == null) || (id == null))
			return null;
		Element el = doc.getElementById(id);
		if (el == null) {
			el = exploreElementById(doc.getDocumentElement(), id);
		}
		return el;
	}
	
	/**
	 * Busca un nodo que tenga la Id indicada que sea hijo del nodo indicado. Busca la id en cualquier atributo que tenga la forma Id, ID, ó id.
	 * 
	 * @param doc
	 * @param id
	 * @return el elemento con la id indicada, <code>null</code> si no hay ningún elemento con esa id.
	 */
	public static Element getElementById(Element padre, String id) {
		Element el = getElementById(padre.getOwnerDocument(), id);
		// Comprueba que el nodo encontrado es hijo
		if (el != null) {
			Node temp = padre;
			while ((temp != null) && (!temp.isSameNode(padre)))
				temp = temp.getParentNode();
			if (temp != null)
				return el;
		}
		return null;
	}
	
	/**
	 * Genera una nueva ID que no esté siendo usada en el documento
	 * 
	 * @param doc
	 * @param prefix
	 * @return
	 */
	public static String newID(Document doc, String prefix) {
		String newID = prefix + rnd.nextInt(RND_MAX_SIZE);
		while (getElementById(doc, newID) != null)
			newID = prefix + rnd.nextInt(RND_MAX_SIZE);
		return newID;
	}

}
