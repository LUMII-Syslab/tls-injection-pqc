package lv.lumii.pqc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class LiboqsParameters
        extends AsymmetricKeyParameter
{
    private byte[] pkEnc, skEnc;
    public LiboqsParameters(boolean privateKey, byte[] pkEnc, byte[] skEnc)
    {
        super(privateKey);
        this.pkEnc = pkEnc;
        this.skEnc = skEnc;
    }

    public byte[] pkEncoded() {
        return this.pkEnc;
    }

    public byte[] skEncoded() {
        return this.skEnc;
    }
}
