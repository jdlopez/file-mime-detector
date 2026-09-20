package io.github.jdlopez;

import java.util.Arrays;
import java.util.Objects;

/**
 * Representa una firma de archivo (magic bytes) ubicada en un offset específico.
 */
public final class OffsetSignature {

    private final int offset;
    private final byte[] signature;
    private final String mimeType;

    public OffsetSignature(int offset, byte[] signature, String mimeType) {
        if (offset < 0) {
            throw new IllegalArgumentException("El offset no puede ser negativo");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("La firma no puede estar vacía");
        }
        if (mimeType == null || mimeType.isBlank()) {
            throw new IllegalArgumentException("El tipo MIME no puede estar vacío");
        }

        this.offset = offset;
        this.signature = signature.clone(); // Copia defensiva
        this.mimeType = mimeType;
    }

    public int getOffset() {
        return offset;
    }

    public byte[] getSignature() {
        return signature.clone(); // Copia defensiva para garantizar inmutabilidad
    }

    public String getMimeType() {
        return mimeType;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OffsetSignature that = (OffsetSignature) o;
        return offset == that.offset &&
                Arrays.equals(signature, that.signature) &&
                Objects.equals(mimeType, that.mimeType);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(offset, mimeType);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }

    @Override
    public String toString() {
        return "OffsetSignature{" +
                "offset=" + offset +
                ", signatureLength=" + signature.length +
                ", mimeType='" + mimeType + '\'' +
                '}';
    }
}