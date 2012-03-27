package es.uji.security.ui.applet;

import java.awt.HeadlessException;
import java.awt.TextField;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;

import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTextField;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;

import org.apache.log4j.Logger;

import es.uji.security.crypto.config.Device;
import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.keystore.X509CertificateHandler;
import es.uji.security.keystore.pkcs11.PKCS11KeyStore;
import es.uji.security.keystore.pkcs12.PKCS12KeyStore;
import es.uji.security.util.i18n.LabelManager;

/**
 * @author Paul
 * 
 *         This class handle all event setup for the application
 * 
 */
public class EventActionHandler
{
	private Logger log = Logger.getLogger(EventActionHandler.class);
	
    private MainWindow mw;
    private AppHandler aph;
    private KeyStoreManager keyStoreManager;

    /**
     * The main constructor
     * 
     * @param mw
     *            The mainWindow of the program.
     */
    public EventActionHandler(MainWindow mw)
    {
        this.mw = mw;
        this.aph = mw.getAppHandler();
        this.keyStoreManager = mw.getKeyStoreManager();
    }

    /**
     * Creates the signature computation action listener
     * 
     * @return res The action listener on a signature creation event
     */
    public java.awt.event.ActionListener getdoSignActionListener()
    {
        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                aph.doSign();
            }
        };

        return res;
    }

    /**
     * Creates the on close action listener
     * 
     * @return res the ActionListener on close
     */
    public java.awt.event.ActionListener getOnCloseActionListener()
    {
        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
            	log.debug("OnClose action called");
            	log.debug("Invoked funtion: " + aph.getJsSignCancel());
            	
                mw.mainFrame.setVisible(false);
                aph.getSignatureHandler().stop();
                
                //TODO: How todo this call?
                //aph.callJavaScriptCallbackFunction(aph.getJsSignCancel(), null);
            }
        };

        return res;
    }

    /**
     * Creates the about action listener
     * 
     * @return res the ActionListener on close
     */
    public java.awt.event.ActionListener getAboutActionListener()
    {
        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                try
                {
                    JOptionPane.showMessageDialog(mw.getMainFrame(), LabelManager
                            .get("ABOUT_DESCRIPTION"), "", JOptionPane.INFORMATION_MESSAGE);
                }
                catch (HeadlessException e1)
                {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
                catch (Exception e1)
                {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        };

        return res;
    }

    /**
     * Creates the help action listener
     * 
     * @return res the ActionListener on close
     */
    public java.awt.event.ActionListener getHelpActionListener()
    {
        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                try
                {
                    JOptionPane.showMessageDialog(mw.getMainFrame(), LabelManager
                            .get("HELP_DESCRIPTION"), "", JOptionPane.INFORMATION_MESSAGE);
                }
                catch (HeadlessException e1)
                {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
                catch (Exception e1)
                {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        };

        return res;
    }

    /**
     * Creates the listener that handles all Certificate Tree Selector complexity like show the pin
     * filed when a certificate is selected, show the certificate info, etc.
     * 
     * @return tsl
     */
    public TreeSelectionListener getJTreeSectionListener()
    {

        TreeSelectionListener tsl = new TreeSelectionListener()
        {
            public void valueChanged(TreeSelectionEvent e)
            {
                JLabel auxLabelPin = mw.getLabelPin();
                // JPasswordField auxPwdField= mw.getPasswordField();
                TextField auxPwdField = mw.textField;
                JTextField auxContentTextField = mw.getContentTextField();

                try
                {
                    X509CertificateHandler selectedNode = (X509CertificateHandler) ((DefaultMutableTreeNode) mw.jTree
                            .getLastSelectedPathComponent()).getUserObject();
                    boolean pk11 = (selectedNode.isPKCS11Provider() || selectedNode
                            .isClauerProvider());

                    auxLabelPin.setVisible(pk11);
                    auxPwdField.setVisible(pk11);
                    auxLabelPin.setEnabled(pk11);

                    String desc = selectedNode.getTokenName().trim();
                    String txtShow = LabelManager.get(desc.replace(' ', '_'));

                    if (txtShow != null)
                        auxLabelPin.setText(txtShow + " PIN:");
                    else
                        auxLabelPin.setText(desc + " PIN:");

                    auxPwdField.setEnabled(pk11);

                    auxPwdField.setText("");
                    auxPwdField.requestFocus();

                    auxContentTextField.setText(selectedNode.getCertificate().toString());
                    mw.getInformationLabelField().setText(LabelManager.get("INFO_SELECT_CERT"));
                }
                catch (Exception exc)
                {
                    auxLabelPin.setVisible(false);
                    auxPwdField.setVisible(false);
                    auxLabelPin.setEnabled(false);
                    auxPwdField.setEnabled(false);
                    auxContentTextField.setText("");
                }
            }
        };

        return tsl;
    }

    /**
     * 
     * Implements the pkcs#12 menu itme action listener that fires an open file dialog when pressed.
     * 
     * @return ActionListener
     */
    public java.awt.event.ActionListener getLoadPKCS12ActionListener()
    {

        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                try
                {
                    JFileChooser chooser = new JFileChooser();
                    int returnVal = chooser.showOpenDialog(mw.getMainFrame());

                    if (returnVal == JFileChooser.APPROVE_OPTION)
                    {
                        System.out.println("You chose to open this file: "
                                + chooser.getSelectedFile().getAbsolutePath());

                        File pkFile = chooser.getSelectedFile().getAbsoluteFile();
                        if (!pkFile.exists())
                        {
                            JOptionPane.showMessageDialog(mw.getMainFrame(), LabelManager
                                    .get("ERROR_FILE_NOT_EXISTS"), "", JOptionPane.ERROR_MESSAGE);
                        }
                        else
                        {
                            try
                            {
                                PKCS12KeyStore pkStore = new PKCS12KeyStore();

                                PasswordPrompt pp = new PasswordPrompt(mw.getMainFrame());
                                char[] pass = pp.getPassword();
                                if (pass != null)
                                {
                                    pkStore.load(new FileInputStream(pkFile), pass);

                                    keyStoreManager.addP12KeyStore(pkStore);
                                    mw.reloadCertificateJTree();
                                }
                            }
                            catch (Exception exc)
                            {
                                JOptionPane.showMessageDialog(mw.getMainFrame(), LabelManager
                                        .get("ERROR_OPEN_PKCS12"), "", JOptionPane.ERROR_MESSAGE);
                                exc.printStackTrace();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    ex.printStackTrace();
                }
            }
        };
        return res;
    }

    /**
     * 
     * Implements the pkcs#11 menu itme action listener that fires an open file dialog when pressed.
     * 
     * @return ActionListener
     */
    public java.awt.event.ActionListener getLoadPKCS11ActionListener()
    {

        ActionListener res = new java.awt.event.ActionListener()
        {
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                try
                {
                    JFileChooser chooser = new JFileChooser();
                    int returnVal = chooser.showOpenDialog(mw.getMainFrame());

                    if (returnVal == JFileChooser.APPROVE_OPTION)
                    {
                        System.out.println("You chose to open this file: "
                                + chooser.getSelectedFile().getAbsolutePath());

                        File pkFile = chooser.getSelectedFile().getAbsoluteFile();
                        
                        if (!pkFile.exists())
                        {
                            JOptionPane.showMessageDialog(mw.getMainFrame(),
                                    "No se encontro fichero", "", JOptionPane.ERROR_MESSAGE);
                        }
                        else
                        {
                            try
                            {
                                PasswordPrompt pp = new PasswordPrompt(mw.getMainFrame());                                
                                char[] pass = pp.getPassword();
                                
                                if (pass != null)
                                {
                                    Device device = new Device();
                                    device.setName("CustomPKCS11");
                                    device.setLibrary(pkFile.getAbsolutePath());
                                    device.setSlot("1");
                                    
                                    keyStoreManager.initPKCS11Device(device, pass);
                                    mw.reloadCertificateJTree();
                                }
                            }
                            catch (Exception exc)
                            {
                                JOptionPane.showMessageDialog(mw.getMainFrame(), LabelManager
                                        .get("ERROR_OPEN_PKCS11"), "", JOptionPane.ERROR_MESSAGE);
                                exc.printStackTrace();
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    ex.printStackTrace();
                }
            }
        };
        return res;
    }
}
