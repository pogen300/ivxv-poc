package ee.vvk.ivotingverification.common.crypto.elgamal;

import static org.junit.Assert.assertTrue;

import ee.vvk.ivotingverification.common.math.group.modp.ModPGroup;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.Test;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERGeneralString;

public class IVV5VVDNegativeCiphertextTest {

    private static final String RFC3526_MODP_3072_P =
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            + "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
            + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
            + "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
            + "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
            + "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
            + "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
            + "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

    @Test
    public void acceptsNegativeAsn1CiphertextComponents() throws Exception {
        BigInteger p = new BigInteger(RFC3526_MODP_3072_P, 16);
        ASN1Encodable[] params = new ASN1Encodable[] {
                new ASN1Integer(p),
                new ASN1Integer(BigInteger.valueOf(4)),
                new DERGeneralString("TEST")
        };
        ModPGroup group = new ModPGroup(params);

        byte[] ciphertext = Base64.getDecoder().decode(new String(Files.readAllBytes(locateFixture()), StandardCharsets.UTF_8).trim());
        ASN1Sequence root;
        try (ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(ciphertext))) {
            root = (ASN1Sequence) in.readObject();
        }

        ASN1Sequence data = (ASN1Sequence) root.getObjectAt(1);
        byte[] aBytes = data.getObjectAt(0).toASN1Primitive().getEncoded();
        byte[] bBytes = data.getObjectAt(1).toASN1Primitive().getEncoded();

        ASN1Primitive aAsn1 = ASN1Primitive.fromByteArray(aBytes);
        assertTrue(((ASN1Integer) aAsn1).getValue().signum() < 0);

        group.ofASN1(aBytes);
        group.ofASN1(bBytes);
        System.out.println("PASS: VVD accepted the negative ASN.1 ciphertext components.");
    }

    private static Path locateFixture() {
        return Path.of(System.getenv("IVXV_POCROOT")).resolve("iv-v5/negative_modp3072_ciphertext.b64");
    }
}
