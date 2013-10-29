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

package es.mityc.firmaJava.policy;

/**
 * Estructura para la validación de políticas de firma
 *
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class PolicyResult {
	
	private String policyId;				// Almacena el id de la politica
	private IValidacionPolicy policyVal;	// Almacena el validador de la policy
	private String policyResult;			// Almacena el resultado de la validación
	
	public PolicyResult(){}
	
	public PolicyResult(String policyId, String policyDesc, String policyAlg,
			String policyDigest, IValidacionPolicy policyVal, String policyResult) {
		this.policyId = policyId;
		this.policyVal = policyVal;
		this.policyResult = policyResult; // Indica un error si es distinto de nulo
	}
	
	/**
	 * Get identificador de la policy
	 * @return Id de la policy
	 */
	public String getPolicyId() {
		return policyId;
	}
	/**
	 * Set identificador de la policy
	 * @param Id de la policy
	 */
	public void setPolicyId(String policyId) {
		this.policyId = policyId;
	}
	/**
	 * Get clase validadora de la policy
	 * @return Instancia al validador de la policy
	 */
	public IValidacionPolicy getPolicyVal() {
		return policyVal;
	}
	/**
	 * Set clase validadora de la policy
	 * @param Instancia del validador de la policy
	 */
	public void setPolicyVal(IValidacionPolicy policyVal) {
		this.policyVal = policyVal;
	}
	/**
	 * Get resultado de validación de la policy, nulo si la policy es válida
	 * @return Descripción del resultado de validación en caso de error
	 */
	public String getPolicyResult() {
		return policyResult;
	}
	/**
	 * Set resultado de validación de la policy
	 * @param Texto descriptivo del resultado de la validación la policy
	 */
	public void setPolicyResult(String policyResult) {
		this.policyResult = policyResult;
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj) {
		if ((obj instanceof IValidacionPolicy) && (policyVal != null)) {
			IValidacionPolicy val = (IValidacionPolicy)obj;
			if (policyVal.getIdentidadPolicy().equals(val.getIdentidadPolicy()))
				return true;
			return false;
		}
		else
			return super.equals(obj);
	}

}
