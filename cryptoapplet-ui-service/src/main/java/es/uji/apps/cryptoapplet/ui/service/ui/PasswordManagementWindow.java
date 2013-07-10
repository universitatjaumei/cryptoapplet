package es.uji.apps.cryptoapplet.ui.service.ui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileOutputStream;
import java.io.IOException;

public class PasswordManagementWindow extends JFrame
{
    private JTextField textField;

    public PasswordManagementWindow()
    {
        super();

        this.setSize(new Dimension(400, 135));
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        this.setTitle("Gestión de la contraseña de firma");
        this.setResizable(false);

        buildCentralPanel();

        this.setVisible(true);

        centerOnScreen();
    }

    private void buildCentralPanel()
    {
        this.textField = new JTextField();

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        panel.add(new JLabel("Contraseña:"));
        panel.add(this.textField);
        panel.add(buildChangePasswordButton());

        this.add(panel);
    }

    private JButton buildChangePasswordButton()
    {
        JButton button = new JButton("Establecer contraseña");
        button.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                try
                {
                    saveNewPasswordOnComputer();
                }
                catch (IOException e1)
                {
                    JOptionPane.showMessageDialog(null, "Error al almacenar la contraseña");
                    e1.printStackTrace();
                }

                closeWindow();
            }
        });

        return button;
    }

    private void saveNewPasswordOnComputer() throws IOException
    {
        FileOutputStream passwordFile = new FileOutputStream(System.getProperty("user.home") + "/.cryptoapplet-auth-token");
        passwordFile.write(textField.getText().getBytes());
        passwordFile.flush();
        passwordFile.close();
    }

    private void closeWindow()
    {
        this.dispose();
    }

    private void centerOnScreen()
    {
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();

        int width = getSize().width;
        int height = getSize().height;
        int x = (screenSize.width - width) / 2;
        int y = (screenSize.height - height) / 2;

        setLocation(x, y);
    }
}
