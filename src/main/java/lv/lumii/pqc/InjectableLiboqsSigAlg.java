package lv.lumii.pqc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto;
import org.bouncycastle.tls.injection.sigalgs.MyMessageSigner;
import org.bouncycastle.tls.injection.sigalgs.PrivateKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.PublicKeyToCipherParameters;
import org.bouncycastle.tls.injection.sigalgs.SigAlgAPI;
import org.bouncycastle.tls.injection.signaturespi.UniversalSignatureSpi;
import org.openquantumsafe.Signature;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureSpi;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class InjectableLiboqsSigAlg
        implements SigAlgAPI {
    private final String name;
    private final Collection<String> aliases;
    private final ASN1ObjectIdentifier oid;
    private final int codePoint;

    public InjectableLiboqsSigAlg(String name, Collection<String> aliases, ASN1ObjectIdentifier oid, int sigCodePoint) {
        this.name = name;
        this.aliases = aliases;
        this.oid = oid;
        this.codePoint = sigCodePoint;
    }

    public String name() {
        return this.name;
    }

    public Collection<String> aliases() {
        return this.aliases;
    }

    public ASN1ObjectIdentifier oid() {
        return this.oid;
    }

    public int codePoint() {
        return this.codePoint;
    }

    @Override
    public boolean isSupportedAlgorithm(ASN1ObjectIdentifier oid)
    {
        return this.oid.equals(oid);
    }

    @Override
    public boolean isSupportedParameter(AsymmetricKeyParameter someKey) {
        return someKey instanceof LiboqsParameters;
    }

    @Override
    public boolean isSupportedPublicKey(Key key)
    {
        return key instanceof LiboqsPublicKey;
    }

    @Override
    public boolean isSupportedPrivateKey(Key key)
    {
        return key instanceof LiboqsPrivateKey;
    }

    @Override
    public AsymmetricKeyParameter createPrivateKeyParameter(PrivateKeyInfo keyInfo) throws IOException {
        byte[] skEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
        byte[] pkEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
        return new LiboqsParameters(true, pkEnc, skEnc);
    }

    @Override
    public PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes) throws IOException {
        LiboqsParameters params = (LiboqsParameters) privateKey;

        AlgorithmIdentifier algorithmIdentifier =
                new AlgorithmIdentifier(oid);
        return new PrivateKeyInfo(algorithmIdentifier, new DEROctetString(params.skEncoded()), attributes, params.pkEncoded());
    }

    @Override
    public AsymmetricKeyParameter createPublicKeyParameter(SubjectPublicKeyInfo keyInfo, Object defaultParams) throws IOException {
        byte[] wrapped = keyInfo.getEncoded(); // ASN1 wrapped
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(wrapped);
        byte[] pkEnc = info.getPublicKeyData().getBytes();

        //AlgorithmIdentifier alg = keyInfo.getAlgorithm(); ??
        return new LiboqsParameters(false, pkEnc, null);
    }

    @Override
    public SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey) throws IOException {
        LiboqsParameters params = (LiboqsParameters) publicKey;

        byte[] encoding = params.pkEncoded();

        // remove the first 4 bytes (alg. params)
        //if (encoding.length == sphincsPlusPKLength+4)
          //  encoding = Arrays.copyOfRange(encoding, 4, encoding.length);

        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);//??? -- does not matter
        // new AlgorithmIdentifier(Utils.sphincsPlusOidLookup(params.getParameters())); // by SK: here BC gets its algID!!!
        return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
    }

    @Override
    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo) throws IOException {

        byte[] sk = keyInfo.getPrivateKey().getOctets();
        byte[] pk = keyInfo.getPublicKeyData().getOctets();

        return new LiboqsPrivateKey(name, pk, sk);
    }

    @Override
    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo) throws IOException {
        byte[] pk = keyInfo.getPublicKeyData().getOctets();
        return new LiboqsPublicKey(name, pk);
    }

    @Override
    public byte[] internalEncodingFor(PublicKey key) {
        return key.getEncoded();
    }

    @Override
    public byte[] internalEncodingFor(PrivateKey key)
    {
        return key.getEncoded();
    }

    @Override
    public byte[] sign(JcaTlsCrypto crypto, byte[] message, byte[] privateKey) throws IOException {
        Signature signer = new Signature(name, privateKey);
        byte[] signature = signer.sign(message);
        return signature;
    }

    @Override
    public boolean verifySignature(byte[] message, byte[] publicKey, DigitallySigned signature) {
        Signature verifier = new Signature(name);
        boolean isValid = verifier.verify(message, signature.getSignature(), publicKey);
        return isValid;
    }

    @Override
    public SignatureSpi signatureSpi(Key publicOrPrivateKey) {
        boolean nameMatches = name.equals(publicOrPrivateKey.getAlgorithm());
        for (String alias: this.aliases)
            nameMatches = nameMatches || alias.equals(publicOrPrivateKey.getAlgorithm());

        if (nameMatches) {
            publicOrPrivateKey = new LiboqsPublicKey(name, publicOrPrivateKey.getEncoded());
        }

        if (publicOrPrivateKey instanceof LiboqsPublicKey) {
            PublicKeyToCipherParameters f1 = (pk) -> {
                if (name.equals(pk.getAlgorithm())) {
                    byte[] b = pk.getEncoded();
                    return new LiboqsParameters(false, b, null);
                }
                else
                    throw new RuntimeException("The given public key does not correspond to the supported algorithm "+name);

            };
            PrivateKeyToCipherParameters f2 = (sk) -> {
                if (sk instanceof LiboqsPrivateKey)
                    return new LiboqsParameters(true, ((LiboqsPrivateKey)sk).pkEncoded(), ((LiboqsPrivateKey)sk).skEncoded());
                else
                    throw new RuntimeException("Not a LiboqsPrivateKey given.");
            };

            return new UniversalSignatureSpi(new NullDigest(),
                    new MyMessageSigner(
                            codePoint,
                            this::sign,
                            this::verifySignature,
                            (params) -> {
                                assert params instanceof LiboqsParameters;
                                LiboqsParameters pkParams = (LiboqsParameters) params;
                                return pkParams.pkEncoded();
                            },
                            (params) -> {
                                assert params instanceof LiboqsParameters;
                                LiboqsParameters skParams = (LiboqsParameters) params;
                                return skParams.skEncoded();
                            }),
                    f1, f2);

        } else
            throw new RuntimeException("Only " + name + " is supported in this implementation of SignatureSpi");
    }

}
