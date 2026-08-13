package ee.ivxv.audit.tools;

import static org.junit.Assert.assertTrue;

import ee.ivxv.audit.AuditContext;
import ee.ivxv.common.cli.CommonArgs;
import ee.ivxv.common.cli.InitialContext;
import ee.ivxv.common.conf.Conf;
import ee.ivxv.common.conf.LocaleConf;
import ee.ivxv.common.service.console.Console;
import ee.ivxv.common.service.console.Progress;
import ee.ivxv.common.service.i18n.I18n;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Test;

/**
 * PoC for UV-V1
 */
public class UVV1AuditIntegrityToolDistrictReassignmentTest {
    private static final String QUESTION_ID = "TESTQUESTION";
    @Test
    public void acceptsDistrictReassignmentAcrossPremixAndAnonBallotBoxes() throws Exception {
        Path generated = locateFixtureDir();
        RecordingConsole console = new RecordingConsole();
        I18n i18n = new SimpleI18n();
        InitialContext initialContext = new InitialContext("uv-v1", new LocaleConf(), console, i18n);
        IntegrityTool tool = new IntegrityTool(new AuditContext(initialContext, new Conf(), new CommonArgs()));
        IntegrityTool.IntegrityArgs toolArgs = createArgs(generated);

        assertTrue(tool.run(toolArgs));
        assertOutputContains(console.lines, "m_integrity_bb_consistent m_yes");
        assertOutputContains(console.lines, "m_integrity_match_anon_logs m_yes");
        assertOutputContains(console.lines, "m_integrity_match_logs m_yes");
        System.out.println(
                "PASS: IntegrityTool accepted the district-reassigned anonymous ballot box.");
    }

    private static IntegrityTool.IntegrityArgs createArgs(Path generated) throws Exception {
        IntegrityTool.IntegrityArgs args = new IntegrityTool.IntegrityArgs();
        args.bb.parse(List.of(generated.resolve("uv-v1.votes.zip").toString()));
        args.anonBoxPath.parse(List.of(generated.resolve("uv-v1-bb-4.json").toString()));
        args.acceptedLogPath.parse(List.of(generated.resolve(QUESTION_ID + ".check.log1").toString()));
        args.squashedLogPath.parse(List.of(generated.resolve(QUESTION_ID + ".squash.log2").toString()));
        args.revokedLogPath.parse(List.of(generated.resolve(QUESTION_ID + ".revoke.log2").toString()));
        args.anonLogPath.parse(List.of(generated.resolve(QUESTION_ID + ".anonymize.log3").toString()));
        args.bbErrorsPath.parse(List.of(generated.resolve("ballotbox_errors.txt").toString()));
        return args;
    }

    private static Path locateFixtureDir() {
        return Path.of(System.getenv("IVXV_POCROOT")).resolve("uv-v1/generated");
    }

    private static void assertOutputContains(List<String> lines, String expected) {
        boolean present = lines.stream().anyMatch(line -> line.contains(expected));
        if (!present) {
            throw new IllegalStateException(
                    "Expected IntegrityTool output line missing: " + expected + "\nActual output:\n"
                            + lines.stream().collect(Collectors.joining("\n")));
        }
    }

    private static final class SimpleI18n implements I18n {
        @Override
        public String get(Enum<?> key, Object... args) {
            if (args == null || args.length == 0) {
                return key.name();
            }
            return key.name() + " " + java.util.Arrays.stream(args)
                    .map(arg -> arg instanceof Enum<?> e ? e.name() : String.valueOf(arg))
                    .collect(Collectors.joining(" "));
        }

        @Override
        public String format(Instant i) {
            return i.toString();
        }
    }

    private static final class RecordingConsole implements Console {
        private final List<String> lines = new ArrayList<>();

        @Override
        public void println() {
            lines.add("");
        }

        @Override
        public void println(String format, Object... args) {
            String line = args == null || args.length == 0 ? format : String.format(format, args);
            lines.add(line);
        }

        @Override
        public void printlnraw(String format, Object... args) {
            println(format, args);
        }

        @Override
        public String readln() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String readPw() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Progress startProgress(String format, long total) {
            return new NoOpProgress();
        }

        @Override
        public Progress startInfiniteProgress(String format, long total) {
            return new NoOpProgress();
        }

        @Override
        public void shutdown() {
        }
    }

    private static final class NoOpProgress implements Progress {
        @Override
        public void increase(int amount) {
        }

        @Override
        public void finish() {
        }
    }
}
