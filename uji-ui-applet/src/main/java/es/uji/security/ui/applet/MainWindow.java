package es.uji.security.ui.applet;

import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.TextField;
import java.awt.Toolkit;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFormattedTextField;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.SwingConstants;

import es.uji.security.keystore.KeyStoreManager;
import es.uji.security.util.i18n.LabelManager;

public class MainWindow
{
    protected EventHandler eventHandler;
    protected JFrame mainFrame;
    protected JPanel mainContentPane;
    protected JScrollPane certificateJTreeScrollPane;
    protected JLabel labelSelectCertTop;
    protected JLabel labelInformation;
    protected JLabel labelPin;
    protected JPasswordField passwordAskField;
    protected TextField textField;
    protected JProgressBar globalProgressBar;
    protected JScrollPane contentScrollPane;
    protected JLabel informationLabelField;
    protected JFormattedTextField contentTextField;
    protected JButton signButton;
    protected JButton cancelButton;
    protected JMenuBar mainMenuBar;
    protected JMenu FileMenu;
    protected JMenuItem loadPkcs11MenuItem;
    protected JMenuItem loadPkcs12MenuItem;
    protected JMenu helpAboutMenu;
    protected JMenuItem helpMenuItem;
    protected JMenuItem aboutMenuItem;
    protected JTextArea showDataTextArea;
    protected JCheckBox showSignatureCheckBox;
    protected JTree jTree;
    protected JScrollPane showDataScrollPane;
    private final JSCommands jsCommands;
    
    private SignatureConfiguration signatureConfiguration;

    public MainWindow(KeyStoreManager keyStoreManager, JSCommands jsCommands)
    {
        this.jsCommands = jsCommands;        
        this.eventHandler = new EventHandler(this, keyStoreManager, jsCommands);

        getMainFrame();
        bringToFront();
    }

    private void bringToFront()
    {
        java.awt.EventQueue.invokeLater(new Runnable()
        {
            public void run()
            {
                mainFrame.toFront();
                mainFrame.repaint();
            }
        });
    }

    public JFrame getMainFrame()
    {
        if (mainFrame == null)
        {
            mainFrame = new JFrame();
            mainFrame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
            mainFrame.addWindowListener(new WindowAdapter()
            {
                public void windowClosing(WindowEvent e)
                {
                    mainFrame.setVisible(false);
                }
            });
            mainFrame.setResizable(false);
            mainFrame.setSize(new Dimension(582, 518));
            mainFrame.setTitle("CryptoApplet");
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

    private JPanel getMainContentPane()
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
            mainContentPane.add(showSignatureCheckBox);
            mainContentPane.add(getGlobalProgressBar(), null);
            mainContentPane.add(getInformationLabelField(), null);
            mainContentPane.add(getContentScrollPane(), null);
            mainContentPane.add(getSignButton(), null);
            mainContentPane.add(getCancelButton(), null);
        }

        return mainContentPane;
    }

    private JScrollPane getCertificateJTreeScrollPane()
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

    public TextField getPasswordTextField()
    {
        if (textField == null)
        {
            textField = new TextField();
            textField.setEchoChar('*');
            textField.setBounds(new Rectangle(170, 423, 130, 24));
            textField.setVisible(false);
            textField.addActionListener(eventHandler.getPasswordTextFieldActionListener());
            textField.setText("");
        }

        return textField;
    }

    public JProgressBar getGlobalProgressBar()
    {
        if (globalProgressBar == null)
        {
            globalProgressBar = new JProgressBar();
            globalProgressBar.setBounds(new Rectangle(311, 218, 255, 14));
            globalProgressBar.setVisible(false);
            globalProgressBar.setValue(0);
        }

        return globalProgressBar;
    }

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

    private JFormattedTextField getContentTextField()
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

    public JLabel getInformationLabelField()
    {
        if (informationLabelField == null)
        {
            informationLabelField = new JLabel();
            informationLabelField.setBounds(new Rectangle(9, 231, 558, 25));
            informationLabelField.setText(LabelManager.get("SELECT_A_CERTIFICATE"));
        }

        return informationLabelField;
    }

    private JButton getSignButton()
    {
        if (signButton == null)
        {
            signButton = new JButton();
            signButton.setBounds(new Rectangle(329, 421, 110, 30));
            signButton.setText(LabelManager.get("BUTTON_SIGN"));
            signButton.addActionListener(eventHandler.getSignButtonActionListener());
        }

        return signButton;
    }

    private JButton getCancelButton()
    {
        if (cancelButton == null)
        {
            cancelButton = new JButton();
            cancelButton.setBounds(new Rectangle(453, 421, 110, 30));
            cancelButton.setText(LabelManager.get("BUTTON_CANCEL"));
            cancelButton.addActionListener(eventHandler.getCancelButtonActionListener());
        }

        return cancelButton;
    }

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

    private JMenuItem getLoadPkcs11MenuItem()
    {
        if (loadPkcs11MenuItem == null)
        {
            loadPkcs11MenuItem = new JMenuItem();
            loadPkcs11MenuItem.setText(LabelManager.get("MENU_LOAD_P11"));
            loadPkcs11MenuItem
                    .addActionListener(eventHandler.getLoadPkcs11MenuItemActionListener());
        }

        return loadPkcs11MenuItem;
    }

    private JMenuItem getLoadPkcs12MenuItem()
    {
        if (loadPkcs12MenuItem == null)
        {
            loadPkcs12MenuItem = new JMenuItem();
            loadPkcs12MenuItem.setText(LabelManager.get("MENU_LOAD_P12"));
            loadPkcs12MenuItem
                    .addActionListener(eventHandler.getLoadPkcs12MenuItemActionListener());
        }

        return loadPkcs12MenuItem;
    }

    private JMenu getHelpAboutMenu()
    {
        if (helpAboutMenu == null)
        {
            helpAboutMenu = new JMenu();
            helpAboutMenu.setText(LabelManager.get("MENU_HELP"));
            helpAboutMenu.add(getHelpMenuItem());
            helpAboutMenu.add(getAboutMenuItem());
        }

        return helpAboutMenu;
    }

    private JMenuItem getHelpMenuItem()
    {
        if (helpMenuItem == null)
        {
            helpMenuItem = new JMenuItem();
            helpMenuItem.setText(LabelManager.get("MENU_HELP"));
            helpMenuItem.addActionListener(eventHandler.getHelpMenuItemActionListener());
        }

        return helpMenuItem;
    }

    private JMenuItem getAboutMenuItem()
    {
        if (aboutMenuItem == null)
        {
            aboutMenuItem = new JMenuItem();
            aboutMenuItem.setText(LabelManager.get("MENU_ABOUT"));
            aboutMenuItem.addActionListener(eventHandler.getAboutMenuItemActionListener());
        }

        return aboutMenuItem;
    }

    private JTree getJTree()
    {
        if (jTree == null)
        {
            jTree = new JTree(eventHandler.getDefaultMutableTreeNodeFromKeyStoreTable());
            jTree.addTreeSelectionListener(eventHandler.getJTreeSelectionListener());
            jTree.expandRow(1);
        }

        return jTree;
    }

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
        {
            mainFrame.repaint(0);
        }
    }

    public JScrollPane getShowDataScrollPane(byte[] in)
    {
        if (showDataTextArea == null)
        {
            showDataTextArea = new JTextArea();
        }

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

    public JCheckBox getShowSignatureCheckBox()
    {
        return showSignatureCheckBox;
    }

    public void loadCertificateTree()
    {
        jTree = null;
        certificateJTreeScrollPane.setViewportView(getJTree());
        certificateJTreeScrollPane.repaint();
    }

    public void hide()
    {
        getMainFrame().setVisible(false);
    }

    public void show(SignatureConfiguration signatureConfiguration)
    {        
        this.signatureConfiguration = signatureConfiguration;
        
        getMainFrame().setVisible(true);
        loadCertificateTree();        
        
        jsCommands.onWindowShow();        
   }
}