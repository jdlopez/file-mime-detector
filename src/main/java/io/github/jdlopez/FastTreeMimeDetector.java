package io.github.jdlopez;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FastTreeMimeDetector {

    public static final String DEFAULT_MIME_OCTET_STREAM = "application/octet-stream";
    private static final String DEFAULT_EMPTY = null;
    // --- Estructuras para Offset 0 (Trie) ---
    private final TrieNode ROOT = new TrieNode();

    private static class TrieNode {
        final Map<Byte, TrieNode> children = new HashMap<>();
        String mimeType;
    }

    // --- Estructuras independientes para Offset > 0 ---
    private final List<OffsetSignature> OFFSET_SIGNATURES = new ArrayList<>();

    private final FileNameMap FILE_NAME_MAP = URLConnection.getFileNameMap();

    /**
     * Parsea el CSV cargando las firmas con offset 0 en el Trie,
     * y las firmas con offset > 0 en la lista secundaria de OffsetSignature.
     */
    public FastTreeMimeDetector(InputStream stream) throws IOException {
        loadFromJSON(stream);
    }
    /**
     * Constructor por defecto: lee /file_sigs.json desde los recursos.
     */
    public FastTreeMimeDetector() throws IOException {
        this(FastTreeMimeDetector.class.getResourceAsStream("/lookup_map.json"));
    }

    private void loadFromJSON(InputStream jsonStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(jsonStream));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            String content = sb.toString();

            // Iniciamos la navegación recursiva del JSON
            parseJsonObject(content, ROOT, new ArrayList<>());

    }

    /**
     * Parsea recursivamente el objeto JSON anidado en Java nativo.
     */
    private void parseJsonObject(String json, TrieNode currentNode, List<Byte> pathBytes) {
        int index = 0;
        int len = json.length();

        while (index < len) {
            // Buscar la siguiente clave "key":
            int keyStart = json.indexOf('"', index);
            if (keyStart == -1) break;
            int keyEnd = json.indexOf('"', keyStart + 1);
            if (keyEnd == -1) break;

            String key = json.substring(keyStart + 1, keyEnd);
            int colonIndex = json.indexOf(':', keyEnd);
            if (colonIndex == -1) break;

            // Determinar si el valor asociado a la clave es un Objeto {} o un Array []
            int valueStart = findNextNonWhitespace(json, colonIndex + 1);
            if (valueStart == -1) break;

            if (json.charAt(valueStart) == '{') {
                int valueEnd = findClosingChar(json, valueStart, '{', '}');
                String subJson = json.substring(valueStart + 1, valueEnd);

                // Si la clave es un byte en hex (ej: "61", "3c", "ff")
                if (key.matches("(?i)[0-9a-f]{2}")) {
                    byte b = (byte) Integer.parseInt(key, 16);
                    TrieNode childNode = currentNode.children.computeIfAbsent(b, k -> new TrieNode());

                    List<Byte> newPath = new ArrayList<>(pathBytes);
                    newPath.add(b);
                    parseJsonObject(subJson, childNode, newPath);
                } else {
                    parseJsonObject(subJson, currentNode, pathBytes);
                }

                index = valueEnd + 1;
            } else if (key.equals("r") && json.charAt(valueStart) == '[') {
                int valueEnd = findClosingChar(json, valueStart, '[', ']');
                String arrayContent = json.substring(valueStart, valueEnd + 1);

                processLeafRecord(arrayContent, currentNode, pathBytes);
                index = valueEnd + 1;
            } else {
                index = keyEnd + 1;
            }
        }
    }

    /**
     * Procesa la hoja "r": [["ext"], [""], offset, ...]
     */
    private void processLeafRecord(String recordArrayJson, TrieNode currentNode, List<Byte> pathBytes) {
        // Captura las extensiones en el primer sub-array: [["ext1", "ext2"], ...] y el offset
        Pattern pattern = Pattern.compile("\\[\\s*\\[(.*?)\\]\\s*,\\s*\\[.*?\\]\\s*,\\s*(\\d+)");
        Matcher matcher = pattern.matcher(recordArrayJson);

        if (matcher.find()) {
            String extBlock = matcher.group(1);
            int offset = Integer.parseInt(matcher.group(2));

            // Extraer la primera extensión válida limpia de comillas
            String firstExt = "";
            for (String token : extBlock.split(",")) {
                String cleaned = token.replaceAll("[\"\\s]", "");
                if (!cleaned.isEmpty()) {
                    firstExt = cleaned;
                    break;
                }
            }

            if (!firstExt.isEmpty()) {
                String mimeType = FILE_NAME_MAP.getContentTypeFor("file." + firstExt);
                if (mimeType != null) {
                    if (offset == 0) {
                        currentNode.mimeType = mimeType;
                    } else {
                        // Si el offset es > 0, se guarda en la lista independiente
                        byte[] sigBytes = new byte[pathBytes.size()];
                        for (int i = 0; i < pathBytes.size(); i++) {
                            sigBytes[i] = pathBytes.get(i);
                        }
                        OFFSET_SIGNATURES.add(new OffsetSignature(offset, sigBytes, mimeType));
                    }
                }
            }
        }
    }

    private int findNextNonWhitespace(String s, int start) {
        for (int i = start; i < s.length(); i++) {
            if (!Character.isWhitespace(s.charAt(i))) return i;
        }
        return -1;
    }

    private int findClosingChar(String s, int start, char openChar, char closeChar) {
        int depth = 0;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == openChar) depth++;
            else if (c == closeChar) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return s.length() - 1;
    }

    private void loadFromCSV(InputStream csvStream) {
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

    private void registerSignature(String hexSequence, String mimeType) {
        String[] hexBytes = hexSequence.split("\\s+");
        TrieNode current = this.ROOT;

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

    private void registerOffsetSignature(int offset, String hexSequence, String mimeType) {
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
    public String detect(InputStream is) throws IOException {
        byte[] header = new byte[64];
        int read = is.read(header);
        if (read <= 0)
            return DEFAULT_EMPTY;

        TrieNode current = ROOT;
        String lastMatch = DEFAULT_MIME_OCTET_STREAM;

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
    public String detectWithOffset(InputStream is, int maxReadBytes) throws IOException {
        // 1. Intentar primero con el árbol (offset 0)
        String mime = detect(is);
        if (!DEFAULT_MIME_OCTET_STREAM.equals(mime)) {
            return mime;
        }

        // 2. Si no hubo coincidencia en offset 0, se leen hasta maxReadBytes para comprobar la lista de offsets
        if (OFFSET_SIGNATURES.isEmpty()) {
            return DEFAULT_MIME_OCTET_STREAM;
        }

        byte[] buffer = new byte[maxReadBytes];
        int bytesRead;

        bytesRead = is.read(buffer);
        if (bytesRead <= 0) // empty file
            return DEFAULT_EMPTY;

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

        return DEFAULT_MIME_OCTET_STREAM;
    }
}