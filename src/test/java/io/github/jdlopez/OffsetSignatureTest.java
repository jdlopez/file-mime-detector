package io.github.jdlopez;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

class OffsetSignatureTest {

    @Test
    @DisplayName("Creación exitosa con valores válidos")
    void testValidInstantiation() {
        byte[] sig = new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47};
        OffsetSignature offsetSig = new OffsetSignature(0, sig, "image/png");

        assertEquals(0, offsetSig.getOffset());
        assertArrayEquals(sig, offsetSig.getSignature());
        assertEquals("image/png", offsetSig.getMimeType());
    }

    @Test
    @DisplayName("Lanza excepción si el offset es negativo")
    void testNegativeOffsetThrowsException() {
        byte[] sig = new byte[]{0x25, 0x50, 0x44, 0x46};
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> new OffsetSignature(-1, sig, "application/pdf")
        );
        assertEquals("El offset no puede ser negativo", ex.getMessage());
    }

    @Test
    @DisplayName("Lanza excepción si la firma es nula o vacía")
    void testInvalidSignatureThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OffsetSignature(0, null, "image/jpeg")
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new OffsetSignature(0, new byte[0], "image/jpeg")
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   "})
    @DisplayName("Lanza excepción si el MIME es nulo o en blanco")
    void testBlankMimeTypeThrowsException(String blankMime) {
        byte[] sig = new byte[]{0x47, 0x49, 0x46};

        assertThrows(
                IllegalArgumentException.class,
                () -> new OffsetSignature(0, sig, null)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new OffsetSignature(0, sig, blankMime)
        );
    }

    @Test
    @DisplayName("Garantiza inmutabilidad mediante copias defensivas")
    void testImmutability() {
        byte[] original = new byte[]{0x00, 0x01, 0x02};
        OffsetSignature offsetSig = new OffsetSignature(10, original, "application/octet-stream");

        // Modificar el array original no debe afectar el objeto
        original[0] = (byte) 0xFF;
        assertNotEquals(original[0], offsetSig.getSignature()[0]);

        // Modificar el array devuelto por el getter tampoco debe afectarlo
        byte[] returned = offsetSig.getSignature();
        returned[0] = (byte) 0xEE;
        assertNotEquals(returned[0], offsetSig.getSignature()[0]);
    }

    @Test
    @DisplayName("Verifica la igualdad por contenido (equals y hashCode)")
    void testEqualsAndHashCode() {
        byte[] sig1 = new byte[]{0x50, 0x4B, 0x03, 0x04};
        byte[] sig2 = new byte[]{0x50, 0x4B, 0x03, 0x04};

        OffsetSignature obj1 = new OffsetSignature(4, sig1, "application/zip");
        OffsetSignature obj2 = new OffsetSignature(4, sig2, "application/zip");

        assertEquals(obj1, obj2);
        assertEquals(obj1.hashCode(), obj2.hashCode());
    }
}