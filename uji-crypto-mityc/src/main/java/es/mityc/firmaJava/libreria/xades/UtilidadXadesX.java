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

package es.mityc.firmaJava.libreria.xades;

import java.util.ArrayList;
import java.util.Iterator;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.I18n;
import es.mityc.firmaJava.libreria.utilidades.NombreNodo;
import es.mityc.firmaJava.libreria.utilidades.UtilidadTratarNodo;
import es.mityc.firmaJava.libreria.xades.errores.BadFormedSignatureException;
import es.mityc.firmaJava.libreria.xades.errores.FirmaXMLError;


/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */
public class UtilidadXadesX implements ConstantesXADES {
	
	private static ArrayList<String> NODOS_DE_X = null;
	static {
		NODOS_DE_X = new ArrayList<String>(6);
		NODOS_DE_X.add(SIGNATURE_VALUE);
		NODOS_DE_X.add(SIGNATURE_TIME_STAMP);
		NODOS_DE_X.add(COMPLETE_CERTIFICATE_REFS);
		NODOS_DE_X.add(COMPLETE_REVOCATION_REFS);
		NODOS_DE_X.add(ATTRIBUTE_CERTIFICATE_REFS);
		NODOS_DE_X.add(ATTRIBUTE_REVOCATION_REFS);
	}

	/**
	 * Obtiene el listado de nodos necesarios para el cálculo del sello de tiempo para XAdES X del tipo 1 (implícito) 
	 * en función del esquema XAdES de firma, a partir del nodo SigAndRefs proporcionado, que actúa como tope
	 * Los nodos necesarios son los siguientes:
	 * 		- SignatureValue
	 * 		- SignatureTimestamp
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 * 
	 * @param esquemaXADES
	 * @param firma
	 * @param nodoSigAndRefs
	 * @return ArrayList<Element> Colección de nodos para el cálculo del sello de tiempo de tipo 1 (implícito) SigAndRefsTimeStamp
	 * @throws BadFormedSignatureException Si no existe, o existe más de un nodo, o no se corresponde con el esquema, según sea el caso 
	 * @throws FirmaXMLError Si se produce un error al obtener los nodods
	 */
	public static ArrayList<Element> obtenerListadoXADESX1imp(String esquemaXADES, Element firma, 
			Element nodoSigAndRefs) throws BadFormedSignatureException, FirmaXMLError	{
				
		// Se crea la estructura de retorno de elementos
		ArrayList<Element> resultado = new ArrayList<Element> ();
		
		// Se agrega el nodo SignatureValue
		Element signatureValueNode = null;
		NodeList signatureValueNodes = firma.getElementsByTagNameNS(SCHEMA_DSIG, SIGNATURE_VALUE);
		if(signatureValueNodes.getLength() == 1)
			signatureValueNode = (Element)signatureValueNodes.item(0);
		else
			// El nodo SignatureValue no se encuentra o no es único. Número de nodos encontrados:
			throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + SIGNATURE_VALUE + ESPACIO +
					I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + signatureValueNodes.getLength());
		
		resultado.add(signatureValueNode);
		
		// Se obtienen el nodo UnsignedSignatureProperties (padre)
		Element UnsignedSignaturePropertiesElement = (Element) nodoSigAndRefs.getParentNode();
		
		if (!(new NombreNodo(esquemaXADES, UNSIGNED_SIGNATURE_PROPERTIES).equals(
				new NombreNodo(UnsignedSignaturePropertiesElement.getNamespaceURI(), UnsignedSignaturePropertiesElement.getLocalName())))) { 
			// El nodo padre de SigAndRefsTimeStamp no es el nodo UnsignedSignatureProperties esperado según esquema
			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_40) + 
					ConstantesXADES.ESPACIO + ConstantesXADES.SIG_AND_REFS_TIME_STAMP + ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_42));
		}
		
		// Se discrimina el tipo de esquema XAdES para incluir los nodos
		if (SCHEMA_XADES_122.equals(esquemaXADES)) { // Búsqueda para el esquemas 1.2.2 (colección de nodos ordenada)

			// Se agregan los nodos SignatureTimeStamp 
			NombreNodo tagName = new NombreNodo(esquemaXADES, SIGNATURE_TIME_STAMP);
			ArrayList<Element> nodosSigTimeStamp = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoSigAndRefs, tagName);
			
			if(nodosSigTimeStamp.size() < 1)
				// No se pudo encontrar el nodo SignatureTimeStamp
				throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_21));
			
			resultado.addAll(nodosSigTimeStamp);
			
			// Se agrega el nodo CompleteCertificateRefs 
			tagName = new NombreNodo(esquemaXADES, COMPLETE_CERTIFICATE_REFS);
			ArrayList<Element> nodosCompleteCertificateRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoSigAndRefs, tagName);
			
			if(!(nodosCompleteCertificateRefs.size() == 1))
				// El nodo CompleteCertificateRefs no existe o no es único. Número de nodos encontrados: 
				throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + COMPLETE_CERTIFICATE_REFS +
						ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodosCompleteCertificateRefs.size());
			
			resultado.addAll(nodosCompleteCertificateRefs);
			
			// Se agrega el nodo CompleteRevocationRefs 
			tagName = new NombreNodo(esquemaXADES, COMPLETE_REVOCATION_REFS);
			ArrayList<Element> nodosCompleteRevocationRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoSigAndRefs, tagName);
			
			if(!(nodosCompleteRevocationRefs.size() == 1))
				// El nodo CompleteRevocationRefs no existe o no es único. Número de nodos encontrados:
				throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + COMPLETE_REVOCATION_REFS +
						ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodosCompleteRevocationRefs.size());
			
			resultado.addAll(nodosCompleteRevocationRefs);
			
			if (SCHEMA_XADES_122.equals(esquemaXADES)) {
			
				// Se agrega el nodo AttributeCertificateRefs, si existe 
				tagName = new NombreNodo(esquemaXADES, ATTRIBUTE_CERTIFICATE_REFS);
				ArrayList<Element> nodosAttributeCertificateRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
						nodoSigAndRefs, tagName);

				if((nodosAttributeCertificateRefs.size() > 1))
					// El nodo AttributeCertificateRefs no es único. número de nodos encontrados:
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + ATTRIBUTE_CERTIFICATE_REFS +
							ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_38) + ESPACIO + nodosAttributeCertificateRefs.size());

				// Si se encontró el nodo, se agrega al array
				if((nodosAttributeCertificateRefs.size() == 1))
					resultado.addAll(nodosAttributeCertificateRefs);
				
				// Se agrega el nodo AttributeRevocationRefs 
				tagName = new NombreNodo(esquemaXADES, ATTRIBUTE_REVOCATION_REFS);
				ArrayList<Element> nodosAttributeRevocationRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
						nodoSigAndRefs, tagName);

				if((nodosAttributeRevocationRefs.size() > 1))
					// El nodo AttributeCertificateRefs no es único. Número de nodos encontrados:
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + ATTRIBUTE_REVOCATION_REFS +
							ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_38) + ESPACIO + nodosAttributeRevocationRefs.size());

				// Si se encontró el nodo, se agrega al array
				if((nodosAttributeRevocationRefs.size() == 1))
					resultado.addAll(nodosAttributeRevocationRefs);
			}
			
		} else { // Búsqueda de nodos para el resto de esquemas (1.3.2 sin orden establecido)
			
			ArrayList<NombreNodo> nodosABuscar = new ArrayList<NombreNodo> ();
			
			// SignatureTimeStamps
			nodosABuscar.add(new NombreNodo(esquemaXADES, SIGNATURE_TIME_STAMP));
			// CompleteCertificateRefs
			nodosABuscar.add(new NombreNodo(esquemaXADES, COMPLETE_CERTIFICATE_REFS));
			// CompleteRevocationRefs
			nodosABuscar.add(new NombreNodo(esquemaXADES, COMPLETE_REVOCATION_REFS));
			// Los nodos AttributeCertificateRefs y AttributeRevocationRefs son opcionales
			nodosABuscar.add(new NombreNodo(esquemaXADES, ATTRIBUTE_CERTIFICATE_REFS));
			nodosABuscar.add(new NombreNodo(esquemaXADES, ATTRIBUTE_REVOCATION_REFS));
			
			// Se realiza la búsqueda
			ArrayList<Element> nodos = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoSigAndRefs, nodosABuscar);
			
			resultado.addAll(nodos);
		}
		
		// Se valida que el resultado obtenido sea correcto
		int[] listaAparicion = new int[6];
		Iterator<Element> it = resultado.iterator();
		int indexAnterior = 0;
		while (it.hasNext()) {
			Element el = it.next();
			int index = NODOS_DE_X.indexOf(el.getLocalName());
			// 0: SignatureValue, 1: SignatureTimeStamp, 2: CompleteCertificateRefs, 
			// 3: CompleteRevocationRefs, 4: AttributeCertificateRefs, 5: AttributeRevocationRefs	

			if (SCHEMA_XADES_122.equals(esquemaXADES)) {
				// Si el valor de index es < indexAnterior => el orden es inválido
				if (index < indexAnterior) {
					// La cadena de nodos para el sello de tiempo no es válida
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_39));
				} else
					indexAnterior = index;
			}
			
			listaAparicion[index]++;
		}
		if ((listaAparicion[0] != 1) || (listaAparicion[1] < 1) || (listaAparicion[2] != 1) || 
				(listaAparicion[3] != 1) || (listaAparicion[4] > 1) || (listaAparicion[5] > 1))
			// La cadena de nodos para el sello de tiempo no es valida
			throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_39));
		
		// Se devuelve la estructura
		return resultado;
	}
	
	/**
	 * Obtiene el listado de nodos necesarios para el cálculo del sello de tiempo para XAdES X del tipo 2 (explícito) 
	 * en función del esquema XAdES de firma, a partir del nodo RefsOnly proporcionado, que actúa como tope
	 * Los nodos necesarios son los siguientes:
	 * 		- CompleteCertificateRefs
	 * 		- CompleteRevocationRefs
	 * 	Opcionalmente en el esquema 1.2.2 y 1.3.2:
	 * 		- AttributeCertificateRefs
	 * 		- AttributeRevocationRefs
	 * 
	 * @param esquemaXADES
	 * @param firma
	 * @param nodo RefsOnlyTimeStamp
	 * @return ArrayList<Element> Colección de nodos para el cálculo del sello de tiempo de tipo 2
	 * @throws BadFormedSignatureException Si no existe, o existe más de un nodo, o no se corresponde con el esquema, según sea el caso 
	 * @throws FirmaXMLError Si se produce un error al obtener los nodods
	 */
	public static ArrayList<Element> obtenerListadoXADESX2exp(String esquemaXADES, Element firma, 
			Element nodoRefsOnly) throws BadFormedSignatureException, FirmaXMLError	{
				
		// Se crea la estructura de retorno de elementos
		ArrayList<Element> resultado = new ArrayList<Element> ();
				
		// Se obtienen el nodo UnsignedSignatureProperties (padre)
		Element UnsignedSignaturePropertiesElement = (Element) nodoRefsOnly.getParentNode();
		
		if (!(new NombreNodo(esquemaXADES, UNSIGNED_SIGNATURE_PROPERTIES).equals(
				new NombreNodo(UnsignedSignaturePropertiesElement.getNamespaceURI(), UnsignedSignaturePropertiesElement.getLocalName())))) { 
			// El nodo padre de RefsOnlyTimeStamp no es el nodo UnsignedSignatureProperties esperado según esquema
			throw new BadFormedSignatureException(I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_40) + 
					ConstantesXADES.ESPACIO + ConstantesXADES.REFS_ONLY_TIME_STAMP + ConstantesXADES.ESPACIO +
					I18n.getResource(ConstantesXADES.LIBRERIAXADES_FIRMAXML_ERROR_42));
		}
		
		// Se discrimina el tipo de esquema XAdES para incluir los nodos
		if (SCHEMA_XADES_122.equals(esquemaXADES)) { // Búsqueda para el esquema 1.2.2 (colección de nodos ordenada)
			
			// Se agregan los nodos CompleteCertificateRefs 
			NombreNodo tagName = new NombreNodo(esquemaXADES, COMPLETE_CERTIFICATE_REFS);
			ArrayList<Element> nodosCompleteCertificateRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoRefsOnly, tagName);
			
			if(!(nodosCompleteCertificateRefs.size() == 1))
				// El nodo CompleteCertificateRefs no existe o no es único. Número de nodos encontrados: 
				throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + COMPLETE_CERTIFICATE_REFS +
						ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodosCompleteCertificateRefs.size());
			
			resultado.addAll(nodosCompleteCertificateRefs);
			
			// Se agregan los nodos CompleteRevocationRefs 
			tagName = new NombreNodo(esquemaXADES, COMPLETE_REVOCATION_REFS);
			ArrayList<Element> nodosCompleteRevocationRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoRefsOnly, tagName);
			
			if(!(nodosCompleteRevocationRefs.size() == 1))
				// El nodo CompleteRevocationRefs no existe o no es único. Número de nodos encontrados:
				throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + COMPLETE_REVOCATION_REFS +
						ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_37) + ESPACIO + nodosCompleteRevocationRefs.size());
			
			resultado.addAll(nodosCompleteRevocationRefs);
	
			if (SCHEMA_XADES_122.equals(esquemaXADES)) {

				// Se agrega el nodo AttributeCertificateRefs, si existe
				tagName = new NombreNodo(esquemaXADES, ATTRIBUTE_CERTIFICATE_REFS);
				ArrayList<Element> nodosAttributeCertificateRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
						nodoRefsOnly, tagName);

				if((nodosAttributeCertificateRefs.size() > 1))
					// El nodo AttributeCertificateRefs no es único. número de nodos encontrados:
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + ATTRIBUTE_CERTIFICATE_REFS +
							ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_38) + ESPACIO + nodosAttributeCertificateRefs.size());

				// Si se encontró el nodo, se agrega al array
				if((nodosAttributeCertificateRefs.size() == 1))
					resultado.addAll(nodosAttributeCertificateRefs);

				// Se agrega el nodo AttributeRevocationRefs 
				tagName = new NombreNodo(esquemaXADES, ATTRIBUTE_REVOCATION_REFS);
				ArrayList<Element> nodosAttributeRevocationRefs = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
						nodoRefsOnly, tagName);

				if((nodosAttributeRevocationRefs.size() > 1))
					// El nodo AttributeCertificateRefs no es único. Número de nodos encontrados:
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_36) + ESPACIO + ATTRIBUTE_REVOCATION_REFS +
							ESPACIO + I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_38) + ESPACIO + nodosAttributeRevocationRefs.size());

				// Si se encontró el nodo, se agrega al array
				if((nodosAttributeRevocationRefs.size() == 1))
					resultado.addAll(nodosAttributeRevocationRefs);
			}	
			
		} else { // Búsqueda de nodos para el resto de esquemas (1.3.2 sin orden establecido)
			
			ArrayList<NombreNodo> nodosABuscar = new ArrayList<NombreNodo> ();			
			// CompleteCertificateRefs
			nodosABuscar.add(new NombreNodo(esquemaXADES, COMPLETE_CERTIFICATE_REFS));
			// CompleteRevocationRefs
			nodosABuscar.add(new NombreNodo(esquemaXADES, COMPLETE_REVOCATION_REFS));
			// Los nodos AttributeCertificateRefs y AttributeRevocationRefs son opcionales
			nodosABuscar.add(new NombreNodo(esquemaXADES, ATTRIBUTE_CERTIFICATE_REFS));
			nodosABuscar.add(new NombreNodo(esquemaXADES, ATTRIBUTE_REVOCATION_REFS));
			
			// Se realiza la búsqueda
			ArrayList<Element> nodos = UtilidadTratarNodo.obtenerNodos(UnsignedSignaturePropertiesElement, 
					nodoRefsOnly, nodosABuscar);
			
			resultado.addAll(nodos);		
		}
		
		// Se valida que el resultado obtenido sea correcto
		int[] listaAparicion = new int[6];
		Iterator<Element> it = resultado.iterator();
		int indexAnterior = 0;
		while (it.hasNext()) {
			Element el = it.next();
			int index = NODOS_DE_X.indexOf(el.getLocalName());
			// 2: CompleteCertificateRefs, 
			// 3: CompleteRevocationRefs, 4: AttributeCertificateRefs, 5: AttributeRevocationRefs	

			if (SCHEMA_XADES_122.equals(esquemaXADES)) {
				// Si el valor de index es < indexAnterior => el orden es inválido
				if (index < indexAnterior) {
					// La cadena de nodos para el sello de tiempo no es válida
					throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_39));
				} else
					indexAnterior = index;
			}
			
			listaAparicion[index]++;
		}
		// Los primeros nodos SignatureValue y SignatureTimeStamp no deben aparecer
		if ((listaAparicion[0] != 0) || (listaAparicion[1] != 0) || (listaAparicion[2] != 1) || 
				(listaAparicion[3] != 1) || (listaAparicion[4] > 1) || (listaAparicion[5] > 1))
			// La cadena de nodos para el sello de tiempo no es valida
			throw new BadFormedSignatureException(I18n.getResource(LIBRERIAXADES_FIRMAXML_ERROR_39));
		
		// Se devuelve la estructura
		return resultado;
	}
}
