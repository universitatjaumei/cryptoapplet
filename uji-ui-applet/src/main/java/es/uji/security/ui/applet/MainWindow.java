package es.uji.security.ui.applet;

import javax.swing.JFrame;
import javax.swing.JPanel;
import java.awt.Dimension;
import java.awt.TextField;
import java.awt.Toolkit;

import javax.swing.JScrollPane;
import javax.swing.JTree;
import javax.swing.JFormattedTextField;
import java.awt.Rectangle;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JLabel;

import javax.swing.JCheckBox;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JButton;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.tree.DefaultMutableTreeNode;

import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.util.i18n.LabelManager;

public class MainWindow
{
    protected JFrame mainFrame = null;
    private JPanel mainContentPane = null;
    private JScrollPane certificateJTreeScrollPane = null;
    private JLabel labelSelectCertTop = null;
    private JLabel labelInformation = null;
    protected JLabel labelPin = null;
    protected JPasswordField passwordAskField = null;
    protected TextField textField = null;
    protected JProgressBar globalProgressBar = null;
    private JScrollPane contentScrollPane = null;
    protected JLabel informationLabelField = null;
    protected JFormattedTextField contentTextField = null;
    protected JButton SignButton = null;
    private JButton cancelButton = null;
    private JMenuBar mainMenuBar = null;
    private JMenu FileMenu = null;
    private JMenuItem loadPkcs11MenuItem = null;
    private JMenuItem loadPkcs12MenuItem = null;
    private JMenu helpAboutMenu = null;
    private JMenuItem helpMenuItem = null;
    private JMenuItem aboutMenuItem = null;
    private JTextArea showDataTextArea = null;
    private JCheckBox showSignatureCheckBox = null;

    protected AppHandler _aph = null;
    private EventActionHandler _evthandler = null;
    protected JTree jTree = null;
    private JScrollPane showDataScrollPane;
    private JLabel showSignatureLabel;
    
    private KeyStoreManager keyStoreManager;

    public MainWindow(KeyStoreManager keyStoreManager, AppHandler aph) throws Exception
    {        
        this.keyStoreManager = keyStoreManager;
        this._aph = aph;
        
        _aph.setMainWindow(this);
        _evthandler = new EventActionHandler(this);
        getMainFrame();
    }

    /**
     * This method initializes mainFrame
     * 
     * @return javax.swing.JFrame
     */
    JFrame getMainFrame() throws Exception
    {
        if (mainFrame == null)
        {
            // mainFrame = new JFrame();
            mainFrame = new JFrame();
            // mainFrame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
            mainFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);

            mainFrame.addWindowListener(new WindowAdapter()
            {
                public void windowClosing(WindowEvent e)
                {
                    mainFrame.setVisible(false);
                    _aph.callJavaScriptCallbackFunction(_aph.getJsSignCancel(), null);
                }
            });
            mainFrame.setResizable(false);
            mainFrame.setSize(new Dimension(582, 518));
            mainFrame.setTitle("CryptoApplet Signer");
            mainFrame.setJMenuBar(getMainMenuBar());
            Toolkit toolkit = Toolkit.getDefaultToolkit();
            int _height = toolkit.getScreenSize().height;
            int _width = toolkit.getScreenSize().width;
            mainFrame.setLocation(_width / 2 - 582 / 2, _height / 2 - 518 / 2);

            mainFrame.setContentPane(getMainContentPane());
            mainFrame.setVisible(true);
        }
        return mainFrame;
    }

    /**
     * This method initializes mainContentPane
     * 
     * @return javax.swing.JPanel
     */
    private JPanel getMainContentPane() throws Exception
    {
        if (mainContentPane == null)
        {
            labelPin = new JLabel();
            labelPin.setBounds(new Rectangle(9, 421, 150, 24));
            labelPin.setHorizontalTextPosition(SwingConstants.TRAILING);
            labelPin.setHorizontalAlignment(SwingConstants.RIGHT);
            labelPin.setText(LabelManager.get("LABEL_PIN_CLAUER"));
            labelPin.setVisible(false);

            labelInformation = new JLabel();
            labelInformation.setBounds(new Rectangle(9, 208, 237, 20));
            labelInformation.setText(LabelManager.get("INFORMATION"));

            labelSelectCertTop = new JLabel();
            labelSelectCertTop.setBounds(new Rectangle(5, 10, 236, 18));
            labelSelectCertTop.setText(LabelManager.get("LABEL_CERTIFICATE_SELECTION"));

            showSignatureCheckBox = new JCheckBox(LabelManager.get("LABEL_SHOW_DATA_ASK"));
            showSignatureCheckBox.setBounds(new Rectangle(311, 398, 255, 14));

            mainContentPane = new JPanel();
            mainContentPane.setLayout(null);
            mainContentPane.add(getCertificateJTreeScrollPane(), null);
            mainContentPane.add(labelSelectCertTop, null);
            mainContentPane.add(labelInformation, null);
            mainContentPane.add(labelPin, null);
            mainContentPane.add(getPasswordTextField(), null);

            // TODO: Research: This functions suffer some encoding problems
            // when used under some 1.6 jvm.
            // mainContentPane.add(getPasswordAskField(), null);

            mainContentPane.add(showSignatureCheckBox);
            mainContentPane.add(getGlobalProgressBar(), null);
            mainContentPane.add(getInformationLabelField(), null);
            mainContentPane.add(getContentScrollPane(), null);
            mainContentPane.add(getSignButton(), null);
            mainContentPane.add(getCancelButton(), null);
        }

        return mainContentPane;
    }

    /**
     * This method initializes certificateJTreeScrollPane
     * 
     * @return javax.swing.JScrollPane
     */
    private JScrollPane getCertificateJTreeScrollPane() throws Exception
    {
        if (certificateJTreeScrollPane == null)
        {
            certificateJTreeScrollPane = new JScrollPane();
            certificateJTreeScrollPane.setBounds(new Rectangle(9, 28, 558, 173));
            certificateJTreeScrollPane.setViewportView(getJTree());
            certificateJTreeScrollPane
                    .setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        }
        return certificateJTreeScrollPane;
    }

    /**
     * This method initializes passwordAskField
     * 
     * @return javax.swing.JPasswordField
     */
    private JPasswordField getPasswordAskField()
    {
        if (passwordAskField == null)
        {
            passwordAskField = new JPasswordField();
            passwordAskField.setBounds(new Rectangle(170, 412, 130, 24));
            passwordAskField.setVisible(false);
            passwordAskField.addActionListener(_evthandler.getdoSignActionListener());
        }
        return passwordAskField;
    }

    /**
     * This method initializes the PasswordTextField
     * 
     * @return TextField
     */
    protected TextField getPasswordTextField()
    {
        if (textField == null)
        {
            textField = new TextField();
            textField.setEchoChar('*');
            textField.setBounds(new Rectangle(170, 423, 130, 24));
            textField.setVisible(false);
            textField.addActionListener(_evthandler.getdoSignActionListener());
        }
        return textField;
    }

    // End Debug only purp.

    /**
     * This method initializes globalProgressBar
     * 
     * @return javax.swing.JProgressBar
     */
    protected JProgressBar getGlobalProgressBar()
    {
        if (globalProgressBar == null)
        {
            globalProgressBar = new JProgressBar();
            globalProgressBar.setBounds(new Rectangle(311, 218, 255, 14));
            globalProgressBar.setVisible(false);
        }
        return globalProgressBar;
    }

    /**
     * This method initializes informationScrollPane
     * 
     * @return javax.swing.JScrollPane
     */
    private JScrollPane getContentScrollPane()
    {
        if (contentScrollPane == null)
        {
            contentScrollPane = new JScrollPane();
            contentScrollPane.setBounds(new Rectangle(9, 259, 558, 130));
            contentScrollPane.setViewportView(getContentTextField());
        }
        return contentScrollPane;
    }

    /**
     * This method initializes informationTextField
     * 
     * @return javax.swing.JTextField
     */
    protected JFormattedTextField getContentTextField()
    {
        if (contentTextField == null)
        {
            contentTextField = new JFormattedTextField();
            contentTextField.setEditable(false);
            contentTextField.setBounds(new Rectangle(9, 257, 558, 30));
            contentTextField.setValue(LabelManager.get("CERTIFICATE_CONTENT_FIELD"));
        }
        return contentTextField;
    }

    /**
     * This method initializes informationTextField
     * 
     * @return javax.swing.JTextField
     */
    protected JLabel getInformationLabelField()
    {
        if (informationLabelField == null)
        {
            informationLabelField = new JLabel();
            informationLabelField.setBounds(new Rectangle(9, 231, 558, 25));
            informationLabelField.setText(LabelManager.get("SELECT_A_CERTIFICATE"));
        }
        return informationLabelField;
    }

    /**
     * This method initializes SignButton
     * 
     * @return javax.swing.JButton
     */
    private JButton getSignButton()
    {
        if (SignButton == null)
        {
            SignButton = new JButton();
            SignButton.setBounds(new Rectangle(329, 421, 110, 30));
            SignButton.setText(LabelManager.get("BUTTON_SIGN"));
            SignButton.addActionListener(_evthandler.getdoSignActionListener());
        }
        return SignButton;
    }

    /**
     * This method initializes cancelButton
     * 
     * @return javax.swing.JButton
     */
    private JButton getCancelButton()
    {

        if (cancelButton == null)
        {
            cancelButton = new JButton();
            cancelButton.setBounds(new Rectangle(453, 421, 110, 30));
            cancelButton.setText(LabelManager.get("BUTTON_CANCEL"));
            cancelButton.addActionListener(_evthandler.getOnCloseActionListener());

        }
        return cancelButton;
    }

    /**
     * This method initializes mainMenuBar
     * 
     * @return javax.swing.JMenuBar
     */
    private JMenuBar getMainMenuBar()
    {
        if (mainMenuBar == null)
        {
            mainMenuBar = new JMenuBar();
            mainMenuBar.add(getFileMenu());
            mainMenuBar.add(getHelpAboutMenu());
        }
        return mainMenuBar;
    }

    /**
     * This method initializes FileMenu
     * 
     * @return javax.swing.JMenu
     */
    private JMenu getFileMenu()
    {
        if (FileMenu == null)
        {
            FileMenu = new JMenu();
            FileMenu.setPreferredSize(new Dimension(51, 20));
            FileMenu.setText(LabelManager.get("MENU_FILE"));
            FileMenu.setSize(new Dimension(71, 20));
            FileMenu.add(getLoadPkcs12MenuItem());
            FileMenu.add(getLoadPkcs11MenuItem());
        }
        return FileMenu;
    }

    /**
     * This method initializes loadPkcs11MenuItem
     * 
     * @return javax.swing.JMenuItem
     */
    private JMenuItem getLoadPkcs11MenuItem()
    {
        if (loadPkcs11MenuItem == null)
        {
            loadPkcs11MenuItem = new JMenuItem();
            loadPkcs11MenuItem.setText(LabelManager.get("MENU_LOAD_P11"));
            loadPkcs11MenuItem.addActionListener(_evthandler.getLoadPKCS11ActionListener());
        }
        return loadPkcs11MenuItem;
    }

    /**
     * This method initializes loadPkcs12MenuItem
     * 
     * @return javax.swing.JMenuItem
     */
    private JMenuItem getLoadPkcs12MenuItem()
    {
        if (loadPkcs12MenuItem == null)
        {
            loadPkcs12MenuItem = new JMenuItem();
            loadPkcs12MenuItem.setText(LabelManager.get("MENU_LOAD_P12"));
            loadPkcs12MenuItem.addActionListener(_evthandler.getLoadPKCS12ActionListener());
        }
        return loadPkcs12MenuItem;
    }

    /**
     * This method initializes helpAboutMenu
     * 
     * @return javax.swing.JMenu
     */
    private JMenu getHelpAboutMenu()
    {
        if (helpAboutMenu == null)
        {
            helpAboutMenu = new JMenu();
            helpAboutMenu.setPreferredSize(new Dimension(20, 5));
            helpAboutMenu.setText("?");
            helpAboutMenu.add(getHelpMenuItem());
            helpAboutMenu.add(getAboutMenuItem());
        }
        return helpAboutMenu;
    }

    /**
     * This method initializes helpMenuItem
     * 
     * @return javax.swing.JMenuItem
     */
    private JMenuItem getHelpMenuItem()
    {
        if (helpMenuItem == null)
        {
            helpMenuItem = new JMenuItem();
            helpMenuItem.setText(LabelManager.get("MENU_HELP"));
            helpMenuItem.addActionListener(_evthandler.getHelpActionListener());
        }
        return helpMenuItem;
    }

    /**
     * This method initializes aboutMenuItem
     * 
     * @return javax.swing.JMenuItem
     */
    private JMenuItem getAboutMenuItem()
    {
        if (aboutMenuItem == null)
        {
            aboutMenuItem = new JMenuItem();
            aboutMenuItem.setText(LabelManager.get("MENU_ABOUT"));
            aboutMenuItem.addActionListener(_evthandler.getAboutActionListener());
        }
        return aboutMenuItem;
    }

    /**
     * This method initializes jTree
     * 
     * @return javax.swing.JTree
     */
    protected JTree getJTree() throws Exception
    {

        if (jTree == null)
        {
            JTreeCertificateBuilder jbt = new JTreeCertificateBuilder();
            DefaultMutableTreeNode dmf = jbt.build(this.keyStoreManager.getKeyStoreTable());
            jTree = new JTree(dmf);
            jTree.addTreeSelectionListener(_evthandler.getJTreeSectionListener());
            jTree.expandRow(1);
        }

        return jTree;
    }

    /**
     * This method reloads a JTree
     * 
     * @return javax.swing.JScrollPane
     */
    protected void reloadCertificateJTree() throws Exception
    {
        jTree = null;
        certificateJTreeScrollPane.setViewportView(getJTree());
        certificateJTreeScrollPane.repaint();
    }

    /**
     * Get method for pin label object
     * 
     * @return labelPin the JLabel object that represents the pin label.
     */
    public JLabel getLabelPin()
    {
        return this.labelPin;
    }

    /**
     * Get method for password input object
     * 
     * @return passwordAskField the JPasswordField object that represents the pin label.
     */
    public JPasswordField getPasswordField()
    {
        return this.passwordAskField;
    }

    /**
     * Method to get the associated AppHandler Object.
     * 
     * @return _aph The AppHandler object associated with MainWindow
     */
    protected AppHandler getAppHandler()
    {
        return this._aph;
    }

    /**
     * @deprecated Init the indeterminate progress on the main window for version 1.
     * 
     */
    public void startIndeterminateProgressBar()
    {
        if (globalProgressBar != null)
        {
            globalProgressBar.setIndeterminate(true);
            globalProgressBar.setVisible(true);
        }
    }

    public void repaint()
    {
        if (mainFrame != null)
            mainFrame.repaint(0);
    }

    public JScrollPane getShowDataScrollPane(byte[] in)
    {

        if (showDataTextArea == null)
            showDataTextArea = new JTextArea();

        showDataTextArea.setText(LabelManager.get("LABEL_SHOW_DATA_DESCRIPTION") + "\n\n"
                + new String(in));

        if (showDataScrollPane == null)
        {
            showDataScrollPane = new JScrollPane();
            showDataScrollPane.setPreferredSize(new Dimension(600, 500));
            showDataScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        }

        showDataScrollPane.setViewportView(showDataTextArea);
        showDataScrollPane.updateUI();

        return showDataScrollPane;
    }

    public boolean isShowSignatureEnabled()
    {
        return showSignatureCheckBox.isSelected();
    }

    public JCheckBox getShowSignatureCheckBox()
    {
        return showSignatureCheckBox;

    }

    public KeyStoreManager getKeyStoreManager()
    {
        return this.keyStoreManager;
    }
}
