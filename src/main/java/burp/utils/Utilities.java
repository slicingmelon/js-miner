package burp.utils;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public final class Utilities {
    private static MontoyaApi api;
    
    public static void setApi(MontoyaApi api) {
        Utilities.api = api;
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
            int start = 0;
            
            while (start < response.length()) {
                int foundIndex = response.indexOf(searchTerm, false, start, response.length());
                if (foundIndex == -1) break;
                
                matches.add(new int[]{foundIndex, foundIndex + searchTerm.length()});
                start = foundIndex + searchTerm.length();
            }
        }

        matches.sort((a, b) -> Integer.compare(a[0], b[0]));

        // Fix overlapping offsets
        for (int i = 0; i < matches.size() - 1; i++) {
            if (matches.get(i)[1] > matches.get(i + 1)[0]) {
                matches.set(i, new int[]{matches.get(i)[0], matches.get(i + 1)[0]});
            }
        }

        return matches;
    }
    
    public static List<int[]> getMatches(ByteArray response, byte[] match) {
        return getMatches(response, List.of(match));
    }
}
