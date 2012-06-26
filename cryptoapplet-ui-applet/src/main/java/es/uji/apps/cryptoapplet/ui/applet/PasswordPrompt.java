package es.uji.apps.cryptoapplet.ui.applet;

import java.awt.Dimension;
import java.awt.Frame;
import java.awt.Rectangle;
import java.awt.Toolkit;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

import es.uji.apps.cryptoapplet.config.i18n.LabelManager;

public class PasswordPrompt extends JDialog
{
    private static final long serialVersionUID = 1L;

    private JPanel jContentPane;
    private JPasswordField jPasswordField;
    private JLabel jLabel;
    private JButton jButton;
    private JButton jCancelButton;

    private char[] password;
    private int width = 350;
    private int height = 125;
    private String title, ask;

    private final LabelManager labelManager;

    public PasswordPrompt(Frame owner, LabelManager labelManager)
    {
        super(owner);
        this.setModal(true);

        this.labelManager = labelManager;
        this.title = labelManager.get("PASSWORD_WINDOW_TITLE");
        this.ask = labelManager.get("PASSWORD_WINDOW_ASK");

        initialize();
    }

    public PasswordPrompt(Frame owner, LabelManager labelManager, String title, String ask)
    {
        super(owner);
        this.setModal(true);

        this.labelManager = labelManager;
        this.title = title;
        this.ask = ask;

        initialize();
    }

    private void initialize()
    {
        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        this.setLocation(dim.width / 2 - width / 2, dim.height / 2 - height / 2);

        this.setResizable(false);
        this.setSize(width, height);
        this.setTitle(title);
        this.setContentPane(getJContentPane());
        this.setVisible(true);
        this.setModal(true);
        this.pack();
    }

    private JPanel getJContentPane()
    {
        if (jContentPane == null)
        {
            jLabel = new JLabel();
            jLabel.setBounds(new Rectangle(27, 16, 90, 31));
            jLabel.setText(ask);
            jContentPane = new JPanel();
            jContentPane.setLayout(null);
            jContentPane.add(getJPasswordField(), null);
            jContentPane.add(jLabel, null);
            jContentPane.add(getJButton(), null);
            jContentPane.add(getCancelJButton(), null);
        }
        return jContentPane;
    }

    private JPasswordField getJPasswordField()
    {
        if (jPasswordField == null)
        {
            jPasswordField = new JPasswordField();
            jPasswordField.setBounds(new Rectangle(120, 16, 195, 32));
            jPasswordField.addActionListener(new java.awt.event.ActionListener()
            {
                public void actionPerformed(java.awt.event.ActionEvent e)
                {
                    btnOkActionPerformed(e);
                }
            });
        }
        return jPasswordField;
    }

    private JButton getJButton()
    {
        if (jButton == null)
        {
            jButton = new JButton(labelManager.get("PASSWORD_WINDOW_ACCEPT"));
            jButton.setBounds(new Rectangle(120, 58, 95, 26));
            jButton.addActionListener(new java.awt.event.ActionListener()
            {
                public void actionPerformed(java.awt.event.ActionEvent e)
                {
                    btnOkActionPerformed(e);
                }
            });
        }
        return jButton;
    }

    private JButton getCancelJButton()
    {
        if (jCancelButton == null)
        {
            jCancelButton = new JButton(labelManager.get("PASSWORD_WINDOW_CANCEL"));
            jCancelButton.setBounds(new Rectangle(220, 58, 95, 26));
            jCancelButton.addActionListener(new java.awt.event.ActionListener()
            {
                public void actionPerformed(java.awt.event.ActionEvent e)
                {
                    btnCancelActionPerformed(e);
                }
            });
        }
        return jCancelButton;
    }

    private void btnOkActionPerformed(java.awt.event.ActionEvent evt)
    {
        password = jPasswordField.getPassword();

        this.setVisible(false);
        this.dispose();
    }

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt)
    {
        password = null;

        this.setVisible(false);
        this.dispose();
    }

    public void reset()
    {
        jPasswordField.setText("");
    }

    public char[] getPassword()
    {
        return password;
    }
}