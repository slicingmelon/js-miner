package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.net.URI;
import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.HashSet;
import java.util.Set;

public final class Utilities {
    private static MontoyaApi api;
    
    public static void setApi(MontoyaApi api) {
        Utilities.api = api;
    }
    
    public static MontoyaApi getApi() {
        return api;
    }
    
    public static void createDirectoriesIfNotExist(Path path) {
        try {
            Files.createDirectories(path);
        } catch (IOException e) {
            api.logging().logToError("Error creating directory: " + e.getMessage());
        }
    }
    
    public static Path handleDuplicateFile(Path filePath) {
        if (!Files.exists(filePath)) {
            return filePath;
        }
        
        String fileName = filePath.getFileName().toString();
        Path parentPath = filePath.getParent();
        int counter = 1;
        
        while (Files.exists(filePath)) {
            String newName = fileName.replaceFirst("[.][^.]+$", "") 
                    + "_" + counter 
                    + fileName.substring(fileName.lastIndexOf("."));
            filePath = parentPath.resolve(newName);
            counter++;
        }
        
        return filePath;
    }
    
    public static boolean isDirEmpty(Path path) {
        try {
            return !Files.list(path).findFirst().isPresent();
        } catch (IOException e) {
            api.logging().logToError("Error checking directory: " + e.getMessage());
            return true;
        }
    }
    
    public static String b64Decode(String encodedString) {
        try {
            return api.utilities().base64Utils().decode(encodedString).toString();
        } catch (IllegalArgumentException e) {
            api.logging().logToError("Error decoding base64: " + e.getMessage());
            return "";
        }
    }
    
    /**
     * Finds all occurrences of unique matches in a response and returns their positions
     * @param response The response to search in as ByteArray
     * @param uniqueMatches List of byte arrays to search for
     * @return List of int arrays containing start and end positions of matches
     */
    public static List<int[]> getMatches(ByteArray response, List<byte[]> uniqueMatches) {
        List<int[]> matches = new ArrayList<>();

        for (byte[] match : uniqueMatches) {
            ByteArray searchTerm = ByteArray.byteArray(match);
            
            // First check if there are any matches at all
            int matchCount = response.countMatches(searchTerm);
            if (matchCount == 0) continue;
            
            // Pre-allocate capacity based on known match count
            List<int[]> termMatches = new ArrayList<>(matchCount);
            int start = 0;
            
            while (start < response.length()) {
                int foundIndex = response.indexOf(searchTerm, false, start, response.length());
                if (foundIndex == -1) break;
                
                termMatches.add(new int[]{foundIndex, foundIndex + searchTerm.length()});
                start = foundIndex + searchTerm.length();
            }
            
            matches.addAll(termMatches);
        }

        // Sort all matches by start position
        matches.sort((a, b) -> Integer.compare(a[0], b[0]));

        // Merge overlapping matches
        if (!matches.isEmpty()) {
            List<int[]> mergedMatches = new ArrayList<>();
            int[] current = matches.get(0);
            
            for (int i = 1; i < matches.size(); i++) {
                int[] next = matches.get(i);
                if (current[1] >= next[0]) {
                    // Merge overlapping matches
                    current[1] = Math.max(current[1], next[1]);
                } else {
                    mergedMatches.add(current);
                    current = next;
                }
            }
            mergedMatches.add(current);
            return mergedMatches;
        }

        return matches;
    }
    
    public static List<int[]> getMatches(ByteArray response, byte[] match) {
        return getMatches(response, List.of(match));
    }
    
    public static boolean isHighEntropy(String s) {
        return getShannonEntropy(s) >= 3.5;
    }

    private static double getShannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }

        int n = s.length();
        Map<Character, Integer> occ = new HashMap<>();

        // Count character occurrences
        for (char c : s.toCharArray()) {
            occ.merge(c, 1, Integer::sum);
        }

        // Calculate entropy
        double entropy = 0.0;
        for (int count : occ.values()) {
            double p = (double) count / n;
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }
    
    /**
     * Converts a URI to a filesystem Path, safely handling separators across OS
     * @param uri The URI to convert
     * @return A Path object representing the URI's path component
     */
    public static Path urlToPath(URI uri) {
        if (uri == null) {
            return Paths.get("");
        }

        Path basePath = Paths.get(FileSystems.getDefault().getSeparator());
        String[] pathSegments = uri.getPath().split("/");

        for (String segment : pathSegments) {
            if (!segment.isEmpty()) {
                // Clean the segment of any potentially unsafe characters
                String cleanSegment = segment.replaceAll("[?%*|:\"<>~]", "_");
                basePath = basePath.resolve(cleanSegment);
            }
        }

        return basePath;
    }
    
    public static byte[] getHTTPResponseBodyHash(HttpRequestResponse requestResponse) {
        if (requestResponse.response() != null) {
            byte[] responseBodyBytes = requestResponse.response().body().getBytes();
            try {
                return java.security.MessageDigest.getInstance("SHA-256").digest(responseBodyBytes);
            } catch (java.security.NoSuchAlgorithmException e) {
                api.logging().logToError("Error creating SHA-256 hash: " + e.getMessage());
                return new byte[0];
            }
        }
        return new byte[0];
    }

    public static Set<HttpRequestResponse> querySiteMap(HttpRequestResponse[] requestResponses, String[] extensions) {
        Set<HttpRequestResponse> uniqueRequests = new HashSet<>();
        for (HttpRequestResponse requestResponse : requestResponses) {
            String url = requestResponse.request().url();
            for (String extension : extensions) {
                if (url.toLowerCase().endsWith("." + extension.toLowerCase())) {
                    uniqueRequests.add(requestResponse);
                    break;
                }
            }
        }
        return uniqueRequests;
    }

    public static String getURLPrefix(HttpRequestResponse requestResponse) {
        return requestResponse.request().url();
    }
}
