package es.uji.apps.cryptoapplet.crypto.junit;

import es.uji.apps.cryptoapplet.crypto.exceptions.SignatureException;
import es.uji.apps.cryptoapplet.crypto.exceptions.ValidationException;
import es.uji.apps.cryptoapplet.crypto.signature.format.SignatureFormatter;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationOptions;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidationResult;
import es.uji.apps.cryptoapplet.crypto.signature.validate.SignatureValidator;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

public abstract class AbstractCryptoTest
{
    protected byte[] sign(Class<? extends SignatureFormatter> formatterClass, SignEnvironment environment) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, SignatureException
    {
        Class[] initTypeArguments = new Class[]{X509Certificate.class, PrivateKey.class, Provider.class};
        Constructor<? extends SignatureFormatter> constructor = formatterClass.getConstructor(initTypeArguments);
        SignatureFormatter formatter = constructor.newInstance(new Object[]{environment.getCertificate(),
                environment.getPrivateKey(), environment.getProvider()});

        return formatter.format(environment.getSignatureOptions());
    }

    protected SignatureValidationResult validate(Class<? extends SignatureValidator> formatterClass, SignEnvironment environment, byte[] signedData) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException, ValidationException
    {
        Class[] initTypeArguments = new Class[]{X509Certificate.class, Provider.class};
        Constructor<? extends SignatureValidator> constructor = formatterClass.getConstructor(initTypeArguments);
        SignatureValidator validator = constructor.newInstance(new Object[]{environment.getCertificate(),
                environment.getProvider()});

        SignatureValidationOptions signatureValidationOptions = new SignatureValidationOptions();
        signatureValidationOptions.setOriginalData(new ByteArrayInputStream(environment.getData()));
        signatureValidationOptions.setSignedData(new ByteArrayInputStream(signedData));

        return validator.validate(signatureValidationOptions);
    }
}
