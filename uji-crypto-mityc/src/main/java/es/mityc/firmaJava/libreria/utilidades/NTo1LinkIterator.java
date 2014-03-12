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

import java.util.Iterator;
import java.util.NoSuchElementException;

public class NTo1LinkIterator<E> implements Iterator<NTo1Link<E>> {
	
	private NTo1Link<E> nextNode;
	
	NTo1LinkIterator(NTo1Link<E> first) {
		nextNode = first;
	}

	public boolean hasNext() {
		return (nextNode != null);
	}

	public NTo1Link<E> next() {
		if (nextNode == null)
			throw new NoSuchElementException();
		NTo1Link<E> node = nextNode;
		nextNode = nextNode.getNext();
		return node;
	}

	public void remove() {
		throw new UnsupportedOperationException();
	}

}
