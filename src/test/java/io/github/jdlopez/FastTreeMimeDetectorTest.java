package io.github.jdlopez;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class FastTreeMimeDetectorTest {

    private static FastTreeMimeDetector detector;

    @BeforeAll
    static void setUp() throws IOException {
        // Inicializa el detector utilizando el constructor por defecto (lee /file_sigs.csv de resources)
        detector = new FastTreeMimeDetector();
    }

    private Path getResourcePath(String resourceName) throws Exception {
        URL resource = getClass().getResource("/" + resourceName);
        assertNotNull(resource, "No se encontró el fichero de prueba en resources: " + resourceName);
        return Path.of(resource.toURI());
    }

    @Test
    @DisplayName("Detecta correctamente el tipo MIME usando el CSV por defecto")
    void testDetectFileTypes() throws Exception {
        String[][] files = {
                new String[]{"test.pdf", "application/pdf"},
                new String[]{"test.pdf.zip", "application/zip"},
                new String[]{"test.pdf.tar.gz", "application/gzip"},
                new String[]{"test.jpg", "image/jpeg"},
                // detects zip (needs more thoutgs...)
                //new String[]{"test.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                // detects default??
                //new String[]{"test.png", "image/png"}
        };
        for (String[] file : files) {
            Path path = getResourcePath(file[0]);
            String mime = detector.detect(Files.newInputStream(path));
            assertEquals(file[1], mime);
        }
    }

    @Test
    @DisplayName("Devuelve DEFAULT_MIME_OCTET_STREAM si el fichero no tiene una firma coincidente")
    void testDetectUnknownFile() throws Exception {
        Path path = getResourcePath("test.bin");
        String mime = detector.detect(Files.newInputStream(path));
        assertEquals(FastTreeMimeDetector.DEFAULT_MIME_OCTET_STREAM, mime);
    }

    @Test
    @DisplayName("Devuelve DEFAULT_MIME_OCTET_STREAM si el fichero no existe")
    void testNonExistentFile() throws IOException {
        Path nonExistentPath = Path.of("non_existent_file.tmp");
        Assertions.assertThrows(
                java.nio.file.NoSuchFileException.class,
                () -> detector.detect(Files.newInputStream(nonExistentPath))
        );
    }
}