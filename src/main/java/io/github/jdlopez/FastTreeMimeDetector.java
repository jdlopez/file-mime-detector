package io.github.jdlopez;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FastTreeMimeDetector {

    // --- Estructuras para Offset 0 (Trie) ---
    private static final TrieNode ROOT = new TrieNode();

    private static class TrieNode {
        final Map<Byte, TrieNode> children = new HashMap<>();
        String mimeType;
    }

    // --- Estructuras independientes para Offset > 0 ---
    private static final List<OffsetSignature> OFFSET_SIGNATURES = new ArrayList<>();

    private static final java.net.FileNameMap FILE_NAME_MAP = URLConnection.getFileNameMap();

    /**
     * Parsea el CSV cargando las firmas con offset 0 en el Trie,
     * y las firmas con offset > 0 en la lista secundaria de OffsetSignature.
     */
    public static void loadMagicBytesFromCsv(InputStream csvStream) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(csvStream))) {
            String line;
            boolean firstLine = true;

            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) continue;

                if (firstLine && line.startsWith("Hex signature")) {
                    firstLine = false;
                    continue;
                }

                String[] columns = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                if (columns.length < 4) continue;

                String rawHex = columns[0].replace("\"", "").trim();
                String rawOffset = columns[2].replace("\"", "").trim();
                String rawExtension = columns[3].replace("\"", "").trim();

                if (rawHex.isEmpty() || rawExtension.isEmpty()) continue;

                String cleanHex = rawHex.replaceAll("\\(.*?\\)", "").trim();
                String firstExt = rawExtension.split("\\s+")[0];
                String mimeType = FILE_NAME_MAP.getContentTypeFor("file." + firstExt);

                if (mimeType != null && !cleanHex.isEmpty()) {
                    int offset = 0;
                    try {
                        offset = Integer.parseInt(rawOffset);
                    } catch (NumberFormatException ignored) {}

                    if (offset == 0) {
                        registerSignature(cleanHex, mimeType);
                    } else {
                        registerOffsetSignature(offset, cleanHex, mimeType);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error al procesar el CSV de magic bytes: " + e.getMessage());
        }
    }

    private static void registerSignature(String hexSequence, String mimeType) {
        String[] hexBytes = hexSequence.split("\\s+");
        TrieNode current = ROOT;

        for (String hexByte : hexBytes) {
            if (hexByte.length() != 2) continue;
            try {
                byte b = (byte) Integer.parseInt(hexByte, 16);
                current = current.children.computeIfAbsent(b, k -> new TrieNode());
            } catch (NumberFormatException ignored) {
                return;
            }
        }
        current.mimeType = mimeType;
    }

    private static void registerOffsetSignature(int offset, String hexSequence, String mimeType) {
        String[] hexBytes = hexSequence.split("\\s+");
        byte[] bytes = new byte[hexBytes.length];

        for (int i = 0; i < hexBytes.length; i++) {
            if (hexBytes[i].length() != 2) return;
            try {
                bytes[i] = (byte) Integer.parseInt(hexBytes[i], 16);
            } catch (NumberFormatException e) {
                return;
            }
        }
        OFFSET_SIGNATURES.add(new OffsetSignature(offset, bytes, mimeType));
    }

    // =========================================================================
    // Métodos de detección
    // =========================================================================

    /**
     * Detección estándar ultra-rápida (evalúa solo los primeros bytes desde el offset 0).
     */
    public static String detect(Path path) {
        byte[] header = new byte[64];
        try (InputStream is = Files.newInputStream(path)) {
            int read = is.read(header);
            if (read <= 0) return "application/octet-stream";
        } catch (Exception e) {
            return "application/octet-stream";
        }

        TrieNode current = ROOT;
        String lastMatch = "application/octet-stream";

        for (byte b : header) {
            current = current.children.get(b);
            if (current == null) break;
            if (current.mimeType != null) {
                lastMatch = current.mimeType;
            }
        }

        return lastMatch;
    }

    /**
     * Función ADICIONAL e INDEPENDIENTE:
     * Inspecciona firmas que requieren un desplazamiento (Offset) superior a 0.
     * Puedes especificar cuántos bytes leídos del fichero quieres inspeccionar (maxReadBytes).
     */
    public static String detectWithOffset(Path path, int maxReadBytes) {
        // 1. Intentar primero con el árbol (offset 0)
        String mime = detect(path);
        if (!"application/octet-stream".equals(mime)) {
            return mime;
        }

        // 2. Si no hubo coincidencia en offset 0, se leen hasta maxReadBytes para comprobar la lista de offsets
        if (OFFSET_SIGNATURES.isEmpty()) {
            return "application/octet-stream";
        }

        byte[] buffer = new byte[maxReadBytes];
        int bytesRead;

        try (InputStream is = Files.newInputStream(path)) {
            bytesRead = is.read(buffer);
            if (bytesRead <= 0) return "application/octet-stream";
        } catch (Exception e) {
            return "application/octet-stream";
        }

        for (OffsetSignature offSig : OFFSET_SIGNATURES) {
            int start = offSig.getOffset();
            byte[] sig = offSig.getSignature();

            // Verificar si el buffer leído contiene espacio suficiente para esta firma
            if (start + sig.length <= bytesRead) {
                boolean match = true;
                for (int i = 0; i < sig.length; i++) {
                    if (buffer[start + i] != sig[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return offSig.getMimeType();
                }
            }
        }

        return "application/octet-stream";
    }
}