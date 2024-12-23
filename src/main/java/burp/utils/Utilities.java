package burp.utils;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.core.ByteArray;

import java.io.IOException;
import java.nio.file.*;
import java.util.Base64;

public final class Utilities {
    
    public static void createDirectoriesIfNotExist(Path path) {
        try {
            Files.createDirectories(path);
        } catch (IOException e) {
            BurpExtender.api.logging().logToError("Error creating directory: " + e.getMessage());
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
            BurpExtender.api.logging().logToError("Error checking directory: " + e.getMessage());
            return true;
        }
    }
    
    public static String b64Decode(String encodedString) {
        try {
            return new String(Base64.getDecoder().decode(encodedString));
        } catch (IllegalArgumentException e) {
            BurpExtender.api.logging().logToError("Error decoding base64: " + e.getMessage());
            return "";
        }
    }
}
