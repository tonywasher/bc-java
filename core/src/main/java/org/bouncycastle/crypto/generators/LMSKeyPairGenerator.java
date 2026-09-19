package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSKeyGenerationParameters;
import org.bouncycastle.crypto.params.LMSPrivateKeyParameters;

public class LMSKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    LMSKeyGenerationParameters param;

    public void init(KeyGenerationParameters param)
    {
        this.param = (LMSKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        LMSPrivateKeyParameters privKey = LMSPrivateKeyParameters.generate(param.getParameters(), param.getRandom());

        return new AsymmetricCipherKeyPair(privKey.getPublicKey(), privKey);
    }
}
