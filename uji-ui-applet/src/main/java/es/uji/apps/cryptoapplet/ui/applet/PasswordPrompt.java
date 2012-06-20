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

    private JPanel jContentPane = null;
    private JPasswordField jPasswordField = null;
    private JLabel jLabel = null;
    private JButton jButton = null;
    private JButton jCancelButton = null;

    private char[] password;
    private int _width = 350, _height = 125;
    private String title, ask;

    public PasswordPrompt(Frame owner)
    {
        super(owner);
        this.setModal(true);
        title = LabelManager.get("PASSWORD_WINDOW_TITLE");
        ask = LabelManager.get("PASSWORD_WINDOW_ASK");
        initialize();
        // System.out.println("Me llaman al constructor");
    }

    public PasswordPrompt(Frame owner, String title, String ask)
    {
        super(owner);
        this.setModal(true);
        this.title = title;
        this.ask = ask;
        initialize();
        // System.out.println("Me llaman al constructor");
    }

    /**
     * This method initializes this
     * 
     * @return void
     */
    private void initialize()
    {

        Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
        this.setLocation(dim.width / 2 - _width / 2, dim.height / 2 - _height / 2);

        this.setResizable(false);
        this.setSize(_width, _height);
        this.setTitle(title);
        this.setContentPane(getJContentPane());
        this.setVisible(true);
        this.setModal(true);
        this.pack();
    }

    /**
     * This method initializes jContentPane
     * 
     * @return javax.swing.JPanel
     */
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

    /**
     * This method initializes jPasswordField
     * 
     * @return javax.swing.JPasswordField
     */
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
                    System.out.println("actionPerformed()"); // TODO Auto-generated Event stub
                                                             // actionPerformed()
                }
            });
        }
        return jPasswordField;
    }

    /**
     * This method initializes jButton
     * 
     * @return javax.swing.JButton
     */
    private JButton getJButton()
    {
        if (jButton == null)
        {
            jButton = new JButton(LabelManager.get("PASSWORD_WINDOW_ACCEPT"));
            jButton.setBounds(new Rectangle(120, 58, 95, 26));
            jButton.addActionListener(new java.awt.event.ActionListener()
            {
                public void actionPerformed(java.awt.event.ActionEvent e)
                {
                    btnOkActionPerformed(e); // TODO Auto-generated Event stub actionPerformed()
                }
            });
        }
        return jButton;
    }

    private JButton getCancelJButton()
    {
        if (jCancelButton == null)
        {
            jCancelButton = new JButton(LabelManager.get("PASSWORD_WINDOW_CANCEL"));
            jCancelButton.setBounds(new Rectangle(220, 58, 95, 26));
            jCancelButton.addActionListener(new java.awt.event.ActionListener()
            {
                public void actionPerformed(java.awt.event.ActionEvent e)
                {
                    btnCancelActionPerformed(e); // TODO Auto-generated Event stub actionPerformed()
                }
            });
        }
        return jCancelButton;
    }

    private void btnOkActionPerformed(java.awt.event.ActionEvent evt)
    {
        // if (evt.getActionCommand().equals("Firmar")){
        password = jPasswordField.getPassword();
        // }

        this.setVisible(false);
        this.dispose();
    }

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt)
    {
        // if (evt.getActionCommand().equals("Firmar")){
        password = null;
        // }

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
