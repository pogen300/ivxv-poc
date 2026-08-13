package ee.ivxv.common.service.bbox.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import ee.ivxv.common.crypto.CryptoUtil;
import ee.ivxv.common.service.bbox.Result;
import ee.ivxv.common.service.bbox.impl.verify.TsVerifier;
import ee.ivxv.common.util.Util;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

public class IVV2PATspDigestMismatchTest {

    @Test
    public void rejectsForgedTimestampResponse() throws Exception {
        Path dir = locateFixtureDir();
        PublicKey collectorPub = loadPublicKey(dir.resolve("collector-public.pem"));
        byte[] responseBytes = Files.readAllBytes(dir.resolve("response.tspreg"));

        TimeStampToken token = new TimeStampToken(new CMSSignedData(responseBytes));
        try {
            new TsVerifier(CryptoUtil.withPublicKey(collectorPub)).verify(token);
            fail("PA accepted the forged timestamp response");
        } catch (ResultException e) {
            assertEquals(Result.REG_NONCE_ALG_MISMATCH, e.result);
            System.out.println(
                    "PASS: PA rejected the timestamp response with REG_NONCE_ALG_MISMATCH.");
        }
    }

    private static Path locateFixtureDir() {
        return Path.of(System.getenv("IVXV_POCROOT")).resolve("iv-v2");
    }

    private static PublicKey loadPublicKey(Path pemPath) throws Exception {
        return CryptoUtil.loadPublicKey(Util.decodePublicKey(pemPath), "RSA");
    }
}
