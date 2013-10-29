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

package es.mityc.firmaJava.libreria.pkcs7;

import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.DisplayMode;
import java.awt.Frame;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Properties;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFormattedTextField;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.WindowConstants;
import javax.swing.text.MaskFormatter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.pkcs11.wrapper.PKCS11Exception;
import es.mityc.firmaJava.configuracion.Configuracion;
import es.mityc.firmaJava.libreria.ConstantesXADES;
import es.mityc.firmaJava.libreria.utilidades.I18n;

/**
 * @author  Ministerio de Industria, Turismo y Comercio
 * @version 0.9 beta
 */

public class ValidaTarjeta extends JDialog implements ConstantesXADES{ 

	/**
	 * Clase que permite seleccionar una tarjeta criptográfica para firmar.
	 */
	//private static final long serialVersionUID = 1L;

static Log logger = LogFactory.getLog(ValidaTarjeta.class);

	
	private Properties tarjetasLibrerias = new Properties();  
	private Configuracion configuracion = new Configuracion();
	private transient KeyStore ks = null;	
	
	private JPanel jPanel = null;
	private JLabel jTarjetaLabel = null;
	private JComboBox jTarjetaComboBox = null;
	private JLabel jLibreriaLabel = null;
	private JTextField jLibreriaTextField = null;
	private JButton jExaminarButton = null;
	private JLabel jPinLabel = null;
	private transient JPasswordField jPinPasswordField = null;
	private JButton jAceptarButton = null;
	private JButton jCancelarButton = null;
	private JLabel jTituloLabel = null;

	
	private PrivateKey pk = null;  
	private JDialog jAgregarTarjetaDialog = null;  
	private JPanel jContentPane = null;
	private JLabel jAgregarLabel = null;
	private JLabel jNombreTarjetaLabel = null;
	private JLabel jNuevaLibreriaLabel = null;
	private JFormattedTextField jNombreTarjetaTextField = null;
	private JTextField jNuevaLibreriaTextField = null;
	private JButton jExaminarButton1 = null;
	private JButton jAceptarAgregarButton = null;
	private JButton jCancelarAgregarButton = null;


	/**
	 * This method initializes 
	 * 
	 */
	public ValidaTarjeta(Frame parent) 
	{		
		super(parent, true);
		initialize();		
		
		//Carga la configuración
		configuracion.cargarConfiguracion();
    	//Establece el idioma según la configuración
    	String locale = configuracion.getValor(LOCALE);
    	FileInputStream fis = null;
        // Configura el idioma
        I18n.setLocale(locale, locale.toUpperCase());
        
		try {
			fis = new FileInputStream(TARJETAS_PROPERTIES);
			tarjetasLibrerias.load(fis);
			Collection claves = tarjetasLibrerias.keySet();
			jTarjetaComboBox.addItem(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_1));
			for (Iterator iter = claves.iterator(); iter.hasNext();) {
				jTarjetaComboBox.addItem((String) iter.next());
			}
			jTarjetaComboBox.addItem(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_2));
			
		} catch (IOException e) {
			JOptionPane.showMessageDialog(this, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_3) + TARJETAS_PROPERTIES, 
					I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_4), JOptionPane.WARNING_MESSAGE);
		}	
		finally{
			try {
				fis.close();
			} catch (IOException e) {
				logger.error(e);
			}
		}
	}

	/**
	 * This method initializes this
	 * 
	 */
	private void initialize() {
        this.setSize(new Dimension(534, 264));
        this.setResizable(false);
        this.setModal(true);
        this.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        this.setContentPane(getJPanel());
        this.setTitle(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_5));	
        
        // Centramos la ventana del applet
      //  Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
        GraphicsDevice[] gs = ge.getScreenDevices();
        
        int screenWidth =0;
        int screenHeight =0;
        int longitud = gs.length;
        for (int i=0; i<longitud; i++) {
            DisplayMode dm = gs[i].getDisplayMode();
            screenWidth = dm.getWidth();
            screenHeight = dm.getHeight();
        }
        
        this.setLocation((int)(screenWidth/2) - (int)(539/2) ,(int)(screenHeight/2) - (int)(497/2) );      
	}

	/**
	 * This method initializes jPanel	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getJPanel() {
		if (jPanel == null) {
			GridBagConstraints gridBagConstraints12 = new GridBagConstraints(); // Título
			gridBagConstraints12.anchor = GridBagConstraints.WEST;
			gridBagConstraints12.gridx = 0;
			gridBagConstraints12.gridy = 0;
			gridBagConstraints12.gridwidth = 3;
			gridBagConstraints12.insets = new Insets(0,10,20,0);
			GridBagConstraints gridBagConstraints21 = new GridBagConstraints(); // Botón Cancelar
			gridBagConstraints21.gridx = 2;
			gridBagConstraints21.gridy = 4;
			gridBagConstraints21.insets = new Insets(20,10,10,10);
			gridBagConstraints21.anchor = GridBagConstraints.WEST;
			GridBagConstraints gridBagConstraints11 = new GridBagConstraints(); // Botón Aceptar
			gridBagConstraints11.gridx = 1;
			gridBagConstraints11.gridy = 4;
			gridBagConstraints11.insets = new Insets(20,10,10,10);
			gridBagConstraints11.anchor = GridBagConstraints.EAST;
			GridBagConstraints gridBagConstraints6 = new GridBagConstraints(); // Campo del PIN
			gridBagConstraints6.anchor = GridBagConstraints.WEST;
			gridBagConstraints6.gridy = 3;
			gridBagConstraints6.gridx = 1;
			GridBagConstraints gridBagConstraints5 = new GridBagConstraints(); // Etiqueta PIN
			gridBagConstraints5.anchor = GridBagConstraints.EAST;
			gridBagConstraints5.gridx = 0;
			gridBagConstraints5.gridy = 3;
			gridBagConstraints5.insets = new Insets(10,10,10,10);
			GridBagConstraints gridBagConstraints4 = new GridBagConstraints(); // Botón Examinar
			gridBagConstraints4.gridx = 3;
			gridBagConstraints4.gridy = 2;
			gridBagConstraints4.insets = new Insets(10,10,10,10);
			GridBagConstraints gridBagConstraints3 = new GridBagConstraints(); // Campo Librería
			gridBagConstraints3.fill = GridBagConstraints.HORIZONTAL;
			gridBagConstraints3.gridy = 2;
			gridBagConstraints3.gridx = 1;
			gridBagConstraints3.gridwidth = 2;
			GridBagConstraints gridBagConstraints2 = new GridBagConstraints(); // Etiqueta Librería
			gridBagConstraints2.anchor = GridBagConstraints.EAST;
			gridBagConstraints2.gridx = 0;
			gridBagConstraints2.gridy = 2;
			gridBagConstraints2.insets = new Insets(10,10,10,10);
			GridBagConstraints gridBagConstraints1 = new GridBagConstraints(); // Selector de Tarjetas
			gridBagConstraints1.anchor = GridBagConstraints.WEST;
			gridBagConstraints1.gridy = 1;
			gridBagConstraints1.gridx = 1;
			gridBagConstraints1.weightx = 1.0;
			gridBagConstraints1.gridwidth = 2;
			GridBagConstraints gridBagConstraints = new GridBagConstraints(); // Etiqueta Tarjetas
			gridBagConstraints.anchor = GridBagConstraints.EAST;
			gridBagConstraints.gridx = 0;
			gridBagConstraints.gridy = 1;
			gridBagConstraints.insets = new Insets(10,10,10,10);
			
			jTituloLabel = new JLabel();
			jTituloLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_6));
			jPinLabel = new JLabel();
			jPinLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_7));
			jLibreriaLabel = new JLabel();
			jLibreriaLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_8));
			jTarjetaLabel = new JLabel();
			jTarjetaLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_9));
			jPanel = new JPanel();
			jPanel.setLayout(new GridBagLayout());
			jPanel.add(jTarjetaLabel, gridBagConstraints);
			jPanel.add(getJTarjetaComboBox(), gridBagConstraints1);
			jPanel.add(jLibreriaLabel, gridBagConstraints2);
			jPanel.add(getJTextField(), gridBagConstraints3);
			jPanel.add(getJExaminarButton(), gridBagConstraints4);
			jPanel.add(jPinLabel, gridBagConstraints5);
			jPanel.add(getJPinPasswordField(), gridBagConstraints6);
			jPanel.add(getJAceptarButton(), gridBagConstraints11);
			jPanel.add(getJCancelarButton(), gridBagConstraints21);
			jPanel.add(jTituloLabel, gridBagConstraints12);
		}
	

		return jPanel;
	}

	/**
	 * This method initializes jTarjetaComboBox	
	 * 	
	 * @return javax.swing.JComboBox	
	 */
	private JComboBox getJTarjetaComboBox() {
		if (jTarjetaComboBox == null) {
			jTarjetaComboBox = new JComboBox();
			jTarjetaComboBox.setPreferredSize(new Dimension(250, 20));
			jTarjetaComboBox.addItemListener(new ItemListener() {
				public void itemStateChanged(ItemEvent e) {
					jLibreriaTextField.setText(tarjetasLibrerias.getProperty((String)jTarjetaComboBox.getSelectedItem()));
				}
			});
		}
		return jTarjetaComboBox;
	}

	/**
	 * This method initializes jLibreriaTextField	
	 * 	
	 * @return javax.swing.JTextField	
	 */
	private JTextField getJTextField() {
		if (jLibreriaTextField == null) {
			jLibreriaTextField = new JTextField();
		}
		return jLibreriaTextField;
	}

	/**
	 * This method initializes jExaminarButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJExaminarButton() {
		if (jExaminarButton == null) {
			jExaminarButton = new JButton();
			jExaminarButton.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_10));			
			jExaminarButton.setPreferredSize(new Dimension(90, 20));
			jExaminarButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
			        final JFileChooser libreria = new JFileChooser();
			        libreria.setDialogTitle(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_11));
			        int returnVal = libreria.showOpenDialog(jPanel);
			        if (returnVal == JFileChooser.APPROVE_OPTION) {
			            jLibreriaTextField.setText(libreria.getSelectedFile().toString());
			        }    
				}
			});
		}
		return jExaminarButton;
	}

	/**
	 * This method initializes jPinPasswordField	
	 * 	
	 * @return javax.swing.JPasswordField	
	 */
	private JPasswordField getJPinPasswordField() {
		if (jPinPasswordField == null) {
			jPinPasswordField = new JPasswordField();
			jPinPasswordField.setPreferredSize(new Dimension(150, 20));
			jPinPasswordField.addKeyListener(new KeyAdapter() 
			{
				public void keyPressed(KeyEvent e) 
				{
					if (e.getKeyCode()==10)
					{
						administrarTarjeta();
					}
				}
			});
		}
		return jPinPasswordField;
	}

	/**
	 * This method initializes jAceptarButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJAceptarButton() {
		if (jAceptarButton == null) {
			jAceptarButton = new JButton();
			jAceptarButton.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_12));
			jAceptarButton.setPreferredSize(new Dimension(90, 20));
			jAceptarButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {     
					administrarTarjeta();
				}
			});
		}
		return jAceptarButton;
	}

	/**
	 * This method initializes jCancelarButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJCancelarButton() {
		if (jCancelarButton == null) {
			jCancelarButton = new JButton();
			jCancelarButton.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_13));
			jCancelarButton.setPreferredSize(new Dimension(90, 20));
			jCancelarButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					ks = null;
					dispose();
				}
			});
		}
		return jCancelarButton;
	}
	
	public PrivateKey getPrivateKey (X509Certificate cert) 
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		pk = null;

		String alias = null;
		Enumeration aliasesEnum;
		aliasesEnum = ks.aliases();
		X509Certificate certKeyStore = null;
		if(aliasesEnum != null)
		{
			while (aliasesEnum.hasMoreElements())
			{
				alias = (String)aliasesEnum.nextElement();
				certKeyStore = (X509Certificate) ks.getCertificate(alias);
				if (certKeyStore.getSerialNumber().equals(cert.getSerialNumber())) 
				{
					pk = (PrivateKey) ks.getKey(alias, jPinPasswordField.getPassword());
				}
			}
		}

		return pk;
	}
	
	public String getAlias (X509Certificate cert) 
		throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
	{
		String alias = null;
		Enumeration aliasesEnum;
		aliasesEnum = ks.aliases();
		X509Certificate certKeyStore = null;
		if(aliasesEnum != null)
		{
			while (aliasesEnum.hasMoreElements())
			{
				alias = (String)aliasesEnum.nextElement();
				certKeyStore = (X509Certificate) ks.getCertificate(alias);
				if (certKeyStore.getSerialNumber().equals(cert.getSerialNumber())) 
				{
					break;
				}
			}
		}
	
		return alias;
	}
	
	public KeyStore getKeyStore()
	{
		return ks;
	}
	
    private static String mensajeErrorConexion(String errorCode)
    {
    	switch (Integer.parseInt(errorCode)) {
    		case -1: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_14);
    		case  2: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_15);
    		case 48: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_16);
    		case 160: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_17);
    		case 164: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_18);
    		case 225: return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_19);
    	}
   		return I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_20);
    }  
    
    
    private void administrarTarjeta()
    {
    	if (((String)jTarjetaComboBox.getSelectedItem()).equals(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_1)))
    	{
    		// No se ha seleccionado ninguna tarjeta
    		JOptionPane.showMessageDialog(jPanel, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_21), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_22), JOptionPane.ERROR_MESSAGE);
    	}
    	else if (((String)jTarjetaComboBox.getSelectedItem()).equals(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_2)))
    	{
    		// Se añade una nueva tarjeta criptográfica
    		agregarTarjeta();
    	}
    	else
    	{
    		// Se ha seleccionado una tarjeta de la lista desplegable
    		validarTarjeta();
    	}
    }
    
    private void validarTarjeta()
    {
        Runnable doWorkRunnable = new Runnable() 
        {
            public void run() {   				
				ConexionTarjeta c = ConexionTarjeta.getInstance();
	    	    try {
					ks = c.conectar(jPinPasswordField.getPassword(), jLibreriaTextField.getText());	
					ValidaTarjeta.this.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
					dispose();
				} catch (ProviderException e1) {
		   	    	JOptionPane.showMessageDialog(jPanel, e1.getMessage(), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_23), JOptionPane.ERROR_MESSAGE);
				} catch (PKCS11Exception e1) {
					String mensajeError = mensajeErrorConexion(String.valueOf(e1.getErrorCode()));
		   	    	JOptionPane.showMessageDialog(jPanel, mensajeError, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_23), JOptionPane.ERROR_MESSAGE);
				}
				ValidaTarjeta.this.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
	    	 }
	    };
   
	   ValidaTarjeta.this.setCursor(new Cursor(Cursor.WAIT_CURSOR));				
	   SwingUtilities.invokeLater(doWorkRunnable); 
    }
    
    private void agregarTarjeta()
    {    
        this.getJAgregarTarjetaDialog();
    	jAgregarTarjetaDialog.setVisible(true);
    }

	/**
	 * This method initializes jAgregarTarjetaDialog	
	 * 	
	 * @return javax.swing.JDialog	
	 */
	private JDialog getJAgregarTarjetaDialog() {
		if (jAgregarTarjetaDialog == null) {
			jAgregarTarjetaDialog = new JDialog();
			jAgregarTarjetaDialog.setSize(new Dimension(527, 207));
			jAgregarTarjetaDialog.setModal(true);
			jAgregarTarjetaDialog.setResizable(false);
			jAgregarTarjetaDialog.setTitle(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_24));
			jAgregarTarjetaDialog.setLocationRelativeTo(this);
			jAgregarTarjetaDialog.setContentPane(getJContentPane());
		}
		return jAgregarTarjetaDialog;
	}

	/**
	 * This method initializes jContentPane	
	 * 	
	 * @return javax.swing.JPanel	
	 */
	private JPanel getJContentPane() {
		if (jContentPane == null) {
			GridBagConstraints gridBagConstraints16 = new GridBagConstraints(); // Botón Cancelar
			gridBagConstraints16.gridx = 2;
			gridBagConstraints16.gridy = 3;
			gridBagConstraints16.weightx = 0.5;
			gridBagConstraints16.insets = new Insets(10,0,20,0);
			
			GridBagConstraints gridBagConstraints15 = new GridBagConstraints(); // Botón Aceptar
			gridBagConstraints15.gridx = 1;
			gridBagConstraints15.gridy = 3;
			gridBagConstraints15.weightx = 0.5;
			gridBagConstraints15.insets = new Insets(10,0,20,0);
			
			GridBagConstraints gridBagConstraints14 = new GridBagConstraints(); // Botón Examinar
			gridBagConstraints14.gridx = 3;
			gridBagConstraints14.gridy = 2;
			gridBagConstraints14.insets = new Insets(0,10,10,10);
			
			GridBagConstraints gridBagConstraints13 = new GridBagConstraints(); // Campo de texto Librería de la Tarjeta
			gridBagConstraints13.fill = GridBagConstraints.HORIZONTAL;
			gridBagConstraints13.gridy = 2;
			gridBagConstraints13.weightx = 1.0;
			gridBagConstraints13.gridx = 1;
			gridBagConstraints13.gridwidth = 2;
			gridBagConstraints13.insets = new Insets(0,10,10,0);
			
			GridBagConstraints gridBagConstraints10 = new GridBagConstraints(); // Campo de texto Nombre de la Tarjeta
			gridBagConstraints10.fill = GridBagConstraints.HORIZONTAL;
			gridBagConstraints10.gridy = 1;
			gridBagConstraints10.weightx = 1.0;
			gridBagConstraints10.gridx = 1;
			gridBagConstraints10.gridwidth = 2;
			gridBagConstraints10.insets = new Insets(0,10,10,0);
			
			GridBagConstraints gridBagConstraints9 = new GridBagConstraints(); // Label Librería de la tarjeta
			gridBagConstraints9.gridx = 0;
			gridBagConstraints9.gridy = 2;
			gridBagConstraints9.anchor = GridBagConstraints.WEST;
			gridBagConstraints9.insets = new Insets(0,10,10,0);
			jNuevaLibreriaLabel = new JLabel();
			jNuevaLibreriaLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_25));
			
			GridBagConstraints gridBagConstraints8 = new GridBagConstraints(); // Label Nombre de la Tarjeta
			gridBagConstraints8.gridx = 0;
			gridBagConstraints8.gridy = 1;
			gridBagConstraints8.anchor = GridBagConstraints.WEST;
			gridBagConstraints8.insets = new Insets(0,10,10,0);
			jNombreTarjetaLabel = new JLabel();
			jNombreTarjetaLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_26));
			
			GridBagConstraints gridBagConstraints7 = new GridBagConstraints(); // Título del panel principal
			gridBagConstraints7.gridx = 0;
			gridBagConstraints7.gridy = 0;
			gridBagConstraints7.gridwidth = 4;
			gridBagConstraints7.anchor = GridBagConstraints.WEST;
			gridBagConstraints7.insets = new Insets(10,10,20,0);
			jAgregarLabel = new JLabel();
			jAgregarLabel.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_27));
			
			jContentPane = new JPanel();
			jContentPane.setLayout(new GridBagLayout());
			jContentPane.add(jAgregarLabel, gridBagConstraints7);
			jContentPane.add(jNombreTarjetaLabel, gridBagConstraints8);
			jContentPane.add(jNuevaLibreriaLabel, gridBagConstraints9);
			jContentPane.add(getJNombreTarjetaTextField(), gridBagConstraints10);
			jContentPane.add(getJNuevaLibreriaTextField(), gridBagConstraints13);
			jContentPane.add(getJExaminarButton1(), gridBagConstraints14);
			jContentPane.add(getJAceptarAgregarButton(), gridBagConstraints15);
			jContentPane.add(getJCancelarAgregarButton(), gridBagConstraints16);
		}
		return jContentPane;
	}

	/**
	 * This method initializes jNombreTarjetaTextField	
	 * 	
	 * @return javax.swing.JTextField	
	 */
	private JFormattedTextField getJNombreTarjetaTextField() {
		if (jNombreTarjetaTextField == null) {
			
			// El nombre de la tarjeta solo acepta letras y números
			// Se agrega la barra baja como separador
			MaskFormatter formato = new MaskFormatter();
			formato.setValidCharacters(CARACTERES_VALIDOS);
			formato.setAllowsInvalid(false);
			try {
				formato.setMask(MASK);
			} catch (ParseException e) {
				// Nunca ocurre
			}
			
			jNombreTarjetaTextField = new JFormattedTextField(formato);
			jNombreTarjetaTextField.setFocusLostBehavior(javax.swing.JFormattedTextField.COMMIT);
		}
		return jNombreTarjetaTextField;
	}

	/**
	 * This method initializes jNuevaLibreriaTextField	
	 * 	
	 * @return javax.swing.JTextField	
	 */
	private JTextField getJNuevaLibreriaTextField() {
		if (jNuevaLibreriaTextField == null) {
			jNuevaLibreriaTextField = new JTextField();
		}
		return jNuevaLibreriaTextField;
	}

	/**
	 * This method initializes jExaminarButton1	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJExaminarButton1() {
		if (jExaminarButton1 == null) {
			jExaminarButton1 = new JButton();
			jExaminarButton1.setPreferredSize(new Dimension(90, 20));
			jExaminarButton1.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_10));
			jExaminarButton1.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
			        final JFileChooser libreria = new JFileChooser();
			        libreria.setDialogTitle(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_11));
			        int returnVal = libreria.showOpenDialog(jPanel);
			        if (returnVal == JFileChooser.APPROVE_OPTION) {
			        	jNuevaLibreriaTextField.setText(libreria.getSelectedFile().toString());
			        }    
				}
			});
		}
		return jExaminarButton1;
	}

	/**
	 * This method initializes jAceptarAgregarButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJAceptarAgregarButton() {
		if (jAceptarAgregarButton == null) {
			jAceptarAgregarButton = new JButton();
			jAceptarAgregarButton.setPreferredSize(new Dimension(90, 20));
			jAceptarAgregarButton.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_12));
			jAceptarAgregarButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					FileOutputStream fos = null;
					if (jNombreTarjetaTextField.getText().trim()==null||jNombreTarjetaTextField.getText().trim().equals(CADENA_VACIA))
					{
						JOptionPane.showMessageDialog(jAgregarTarjetaDialog, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_28), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_22), JOptionPane.ERROR_MESSAGE);
					}
					else if (jNuevaLibreriaTextField.getText()==null||jNuevaLibreriaTextField.getText().equals(CADENA_VACIA))
					{
						JOptionPane.showMessageDialog(jAgregarTarjetaDialog, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_29), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_22), JOptionPane.ERROR_MESSAGE);
					}
					else
					{
				    	tarjetasLibrerias.setProperty(jNombreTarjetaTextField.getText().trim(), jNuevaLibreriaTextField.getText());
				    	try {
				    		fos = new FileOutputStream(TARJETAS_PROPERTIES);
							tarjetasLibrerias.store(fos,null);
							jTarjetaComboBox.removeItem(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_2));
							jTarjetaComboBox.addItem(jNombreTarjetaTextField.getText().trim());
							jTarjetaComboBox.addItem(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_2));
							jTarjetaComboBox.setSelectedIndex(0);
						} catch (FileNotFoundException e1) {
							JOptionPane.showMessageDialog(jAgregarTarjetaDialog, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_30), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_31), JOptionPane.ERROR_MESSAGE);
						} catch (IOException e1) {
							JOptionPane.showMessageDialog(jAgregarTarjetaDialog, I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_32), I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_31), JOptionPane.ERROR_MESSAGE);
						}
						finally{
							if (fos != null){
								try {
									fos.close();
								} catch (IOException e1) {
									logger.error(e1);
								}
							}
						}
						jAgregarTarjetaDialog.setVisible(false);
					}
				}
			});
		}
		return jAceptarAgregarButton;
	}

	/**
	 * This method initializes jCancelarAgregarButton	
	 * 	
	 * @return javax.swing.JButton	
	 */
	private JButton getJCancelarAgregarButton() {
		if (jCancelarAgregarButton == null) {
			jCancelarAgregarButton = new JButton();
			jCancelarAgregarButton.setPreferredSize(new Dimension(90, 20));
			jCancelarAgregarButton.setText(I18n.getResource(LIBRERIAXADES_VALIDARTARJETA_TEXTO_13));
			jCancelarAgregarButton.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					jAgregarTarjetaDialog.setVisible(false);
				}
			});
		}
		return jCancelarAgregarButton;
	}

}  
