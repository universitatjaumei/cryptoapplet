package es.uji.security.ui.applet;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;

import es.uji.security.keystore.KeyStoreManager;

public class EventHandler
{
    private final KeyStoreManager keyStoreManager;
    private final JSCommands jsCommands;
    private final MainWindow mainWindow;

    public EventHandler(MainWindow mainWindow, KeyStoreManager keyStoreManager, JSCommands jsCommands)
    {
        this.mainWindow = mainWindow;
        this.keyStoreManager = keyStoreManager;
        this.jsCommands = jsCommands;
    }
    
    public ActionListener getPasswordTextFieldActionListener()
    {
        return null;
    }

    public ActionListener getSignButtonActionListener()
    {
        return null;
    }

    public ActionListener getCancelButtonActionListener()
    {
        return new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                mainWindow.hide();
                jsCommands.onSignCancel();                
            }
        };
    }

    public ActionListener getLoadPkcs11MenuItemActionListener()
    {
        return null;
    }

    public ActionListener getLoadPkcs12MenuItemActionListener()
    {
        return null;
    }

    public ActionListener getHelpMenuItemActionListener()
    {
        return null;
    }

    public ActionListener getAboutMenuItemActionListener()
    {
        return null;
    }

    public DefaultMutableTreeNode getDefaultMutableTreeNodeFromKeyStoreTable()
    {
        JTreeCertificateBuilder jbt = new JTreeCertificateBuilder();
        return jbt.build(keyStoreManager.getKeyStoreTable());
    }

    public TreeSelectionListener getJTreeSelectionListener()
    {
        return null;
    }
}