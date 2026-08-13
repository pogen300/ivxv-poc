package ee.ivxv.common.cli;

import ee.ivxv.common.conf.Conf;
import ee.ivxv.common.service.bbox.BboxHelper;
import ee.ivxv.common.service.bbox.impl.BboxHelperImpl;
import ee.ivxv.common.service.container.Container;
import ee.ivxv.common.service.container.ContainerReader;
import ee.ivxv.common.service.container.DataFile;
import ee.ivxv.common.service.container.InvalidContainerException;
import ee.ivxv.common.service.container.Signature;
import ee.ivxv.common.service.container.Subject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * Auditor tests use raw JSON fixtures for config-style inputs instead of wrapping them in BDOC.
 */
public class TestContextFactory extends ContextFactory {

    @Override
    public ContainerReader getContainer(Conf conf, int nThreads) {
        return new RawFileContainerReader();
    }

    @Override
    public BboxHelper getBbox(Conf conf, ContainerReader container) {
        return new BboxHelperImpl(conf, container);
    }

    private static final class RawFileContainerReader implements ContainerReader {
        @Override
        public boolean isContainer(Path path) {
            return Files.isRegularFile(path);
        }

        @Override
        public Container read(String path) throws InvalidContainerException {
            try {
                return wrap(path, Files.readAllBytes(Path.of(path)));
            } catch (IOException e) {
                throw new InvalidContainerException(path, e);
            }
        }

        @Override
        public Container read(String path, int limitSize) throws InvalidContainerException {
            return read(path);
        }

        @Override
        public Container read(InputStream input, String ref) throws InvalidContainerException {
            try {
                return wrap(ref, input.readAllBytes());
            } catch (IOException e) {
                throw new InvalidContainerException(ref, e);
            }
        }

        @Override
        public byte[] combine(byte[] data, byte[] ocsp, byte[] ts, String tsC14nAlg) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] getTimestampData(byte[] data, String c14nAlg) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getFileExtension() {
            return "raw";
        }

        private static Container wrap(String ref, byte[] bytes) {
            DataFile file = new DataFile() {
                @Override
                public String getName() {
                    return ref;
                }

                @Override
                public InputStream getStream() {
                    return new ByteArrayInputStream(bytes);
                }
            };
            Signature signature = new Signature(
                    new Subject("TEST", "TEST"),
                    Instant.EPOCH,
                    Signature.Profile.BDOC_TS,
                    new byte[0]);
            return new Container(List.of(file), List.of(signature));
        }
    }
}
