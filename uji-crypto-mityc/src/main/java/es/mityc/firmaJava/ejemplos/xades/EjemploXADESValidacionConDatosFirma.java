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
 * Copyright 2007 Ministerio de Industria, Turismo y Comercio
 * 
 */

package es.mityc.firmaJava.ejemplos.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.xades.DatosFirma;
import es.mityc.firmaJava.libreria.xades.DatosOCSP;
import es.mityc.firmaJava.libreria.xades.DatosSelloTiempo;
import es.mityc.firmaJava.libreria.xades.ResultadoValidacion;
import es.mityc.firmaJava.libreria.xades.ValidarFirmaXML;
import es.mityc.firmaJava.policy.PolicyResult;

/**
 * Clase de ejemplo que ilustra los datos accesibles tras la validación XAdES
 * utilizando la librería XADES
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class EjemploXADESValidacionConDatosFirma {

	private final static String FICHERO_XADES_VALIDO = "out.xml";

	public static void main(String[] args) {
		EjemploXADESValidacionConDatosFirma p = new EjemploXADESValidacionConDatosFirma();
		p.validarFichero(System.getProperty("user.dir") + "/");
	}

	/**
	 * Método análogo al comentado en el proyecto EjemploXADESValidacion, con la 
	 * información mostrada por consola ampliada en profundidad
	 * @param fichero
	 */
	public void validarFichero(String ruta) {

		// Se declara la estructura de datos que almacenará el resultado de la validación
		ResultadoValidacion result = null;

		// Se captura el fichero a validar
		File file = new File(ruta + FICHERO_XADES_VALIDO);

		// Se parsea el fichero a validar
		FileInputStream fis = null;
		byte[] datos = null;
		try {
			fis = new FileInputStream(file);
			datos = new byte[fis.available()];
			fis.read(datos);
		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Se instancia el validador y se realiza la validación
		try {
			ValidarFirmaXML vXml = new ValidarFirmaXML();
			result = vXml.validar(datos, ruta, null);
		} catch (Exception e) {
			e.printStackTrace();
		}

		// Se muestra por consola el resultado de la validación
		boolean isValid = result.isValidate();
		System.out.println("\n-----------------");
		System.out.println("--- RESULTADO ---");
		System.out.println("-----------------");

		if (isValid) {
			System.out.println("La firma es valida");
		} else {
			System.out.println("La firma NO es valida\n" + result.getLog());
			return;
		}

		// se muestran los datos contenidos en el resultado de la firma
		try {
			mostrarDatosFirmaXADES(result);
		} catch (RemoteException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Método que muestra por consola la estructura de datos resultado de la validación XAdES
	 * @param datos
	 * @throws RemoteException
	 */
	private void mostrarDatosFirmaXADES(ResultadoValidacion datos) throws RemoteException {

		// Formateador de fechas
		SimpleDateFormat formateador = new SimpleDateFormat("dd/MM/yyyy");

		System.out.println("\n\n-------------------------");
		System.out.println("--- DATOS DE LA FIRMA ---");
		System.out.println("-------------------------");

		// Se obtiene el último nivel XAdES válido
		String nivVal = datos.getNivelValido();
		if (nivVal == null || nivVal == "")
			nivVal = "No se pudo validar ningun nivel";
		System.out.println("Ultimo nivel valido: " + nivVal);
		// El método datos.getEnumNivel() devuelve la misma información en formato EnumFormatoFirma

		// Se obtiene el Log de error (estará vacío si no hubo ninguno)
		String errores = datos.getLog();
		if (errores == null || errores == "")
			errores = "No hay errores.";
		System.out.println("Error: " + errores);

		// Supuesto nivel sin válidar (si la firma es válida, coincidirá con getNivelValido)
		System.out.println("El nivel de la firma llega hasta: " + datos.getEnumNivel());

		// Se puede obtener la firma ya parseada en formato Document mediante el método datos.getDoc()

		// Obtenemos los datos de firma obtenidos
		DatosFirma datosFirma = datos.getDatosFirma();
		if (datosFirma == null)
			return;

		// Fecha de firma
		Date fecha = datosFirma.getFechaFirma();
		if (fecha != null) {
			String fechaFormateada = formateador.format(fecha);
			System.out.println("Fecha de firma: " + fechaFormateada);
		}

		// Obtenemos el certificado firmante
		System.out.println("\n ----- Certificado de firma -----");
		X509Certificate cert = (X509Certificate)datosFirma.getCadenaFirma().getCertificates().get(0);
		System.out.println("Emitido para: " + cert.getSubjectX500Principal().getName());
		System.out.println("Emitido por: " + cert.getIssuerX500Principal().getName());
		String emision = formateador.format(cert.getNotBefore());
		System.out.println("Emitido el: " + emision);
		String caducidad = formateador.format(cert.getNotAfter());
		System.out.println("Caduca el: " + caducidad);
		System.out.println("------------------------------");

		// Resultados OCSP
		ArrayList<DatosOCSP> arrayOCSP = datosFirma.getDatosOCSP();
		if (arrayOCSP != null) {
			int nodesOCSPRefLength = arrayOCSP.size();
			System.out.println("\n\nHay " + nodesOCSPRefLength + " respuestas OCSP");
			for (int i=0; i<nodesOCSPRefLength; i++) {
				DatosOCSP datosOCSP = arrayOCSP.get(i);
				System.out.println("--- Respuesta OCSP numero " + (i + 1)+ "---");			
				// Si la estructura está vacía, indica que no pasó la validación
				String respuesta = null;
				if (datosOCSP != null)
					respuesta = "Certificado validado correctamente";
				else
					respuesta = "Certificado Revocado";

				System.out.println("Certificado Consultado: " + datosOCSP.getCertConsultado());
				System.out.println("Fecha de la consulta: " + datosOCSP.getFechaConsulta());
				System.out.println("Resultado de la validacion: " + respuesta);
				System.out.println("------------------------------");
			}
		}

		// Sellos de tiempo
		Iterator<DatosSelloTiempo> itTSs = datosFirma.getDatosSelloTiempo().iterator();
		System.out.println("\n\nHay " + datosFirma.getDatosSelloTiempo().size() + " sellos de tiempo");
		int x = 0;
		while (itTSs.hasNext()) {
			DatosSelloTiempo dst = itTSs.next();
			x++;
			System.out.println("--- Sello de tiempo numero " + x + "---");
			System.out.println("Emisor: " + dst.getEmisor().getName());
			System.out.println("Fecha: " + dst.getFecha());
			Long precision = dst.getPrecision();
			if (precision > 0)
				System.out.println("Precision: " + dst.getPrecision());
			else
				System.out.println("Precision: No hay datos de la precisión");
			System.out.println("------------------------------");
		}

		// Políticas
		ArrayList<PolicyResult> arrayPoliticas = datosFirma.getPoliticas();

		if (arrayPoliticas != null) {
			int nodesPoliticasLength = arrayPoliticas.size();
			System.out.println("\n\nHay " + nodesPoliticasLength + " politicas validadas");
			for (int i=0; i<nodesPoliticasLength; i++) {
				PolicyResult politica = arrayPoliticas.get(i);
				System.out.println("--- Politica numero " + (i + 1) + "---");
				StringBuffer policyRes = new StringBuffer(politica.getPolicyResult());
				if (policyRes == null) {
					if (ConstantesXADES.LIBRERIAXADES_IMPLIEDPOLICY.equals(politica.getPolicyId())) {
						politica.setPolicyId("Politica implicita");
						policyRes = new StringBuffer("La politica no pudo ser validada");
					}
				} else {
					policyRes = new StringBuffer("Politica invalidada");
					policyRes.append(policyRes);
				}

				System.out.println("Politica incuida: " + politica.getPolicyId());
				System.out.println("Resultado de la validacion: " + policyRes.toString());
				System.out.println("------------------------------");
			}
		}

		// Roles
		Iterator<String> itRoles = datos.getDatosFirma().getRoles().iterator();
		System.out.println("\n\n---- Roles ----");
		while (itRoles.hasNext()) {
			System.out.println("Rol: " + itRoles.next());
		}
	}
}
