package burp.utils;

import burp.api.montoya.MontoyaApi;
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
    
    public static List<int[]> getMatches(ByteArray response, List<byte[]> uniqueMatches) {
        List<int[]> matches = new ArrayList<>();
        byte[] responseBytes = response.getBytes();

        for (byte[] match : uniqueMatches) {
            int start = 0;
            while (start < responseBytes.length) {
                int foundIndex = api.utilities().byteUtils().indexOf(responseBytes, match, false, start, responseBytes.length);
                if (foundIndex == -1) break;
                
                matches.add(new int[]{foundIndex, foundIndex + match.length});
                start = foundIndex + match.length;
            }
        }

        // Sort matches by start index using primitive comparison
        matches.sort((a, b) -> Integer.compare(a[0], b[0]));

        // Fix overlapping offsets
        for (int i = 0; i < matches.size() - 1; i++) {
            if (matches.get(i)[1] > matches.get(i + 1)[0]) {
                matches.set(i, new int[]{matches.get(i)[0], matches.get(i + 1)[0]});
            }
        }

        return matches;
    }
}
