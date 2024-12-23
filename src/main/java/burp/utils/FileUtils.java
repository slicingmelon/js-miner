package burp.utils;

import burp.api.montoya.MontoyaApi;
import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtils {
    private static MontoyaApi api;
    
    public static void setApi(MontoyaApi api) {
        FileUtils.api = api;
    }

    public static boolean saveFile(String sourceFilePath, byte[] data, Path outputDirPath) {
        Path filePath = Paths.get(sourceFilePath);
        String fileName = filePath.getFileName().toString();
        Utilities.createDirectoriesIfNotExist(getTempDirPath(outputDirPath));
        
        try {
            Path tempFile = Files.createTempFile(getTempDirPath(outputDirPath), fileName, ".js");
            Files.write(tempFile, data);
            String trustedFileName = secureFile(sourceFilePath, outputDirPath);
            Path trustedPath = Paths.get(trustedFileName);
            trustedPath = Utilities.handleDuplicateFile(trustedPath);
            Files.move(tempFile, trustedPath);
            
            if (!Utilities.isDirEmpty(outputDirPath)) {
                return true;
            }
        } catch (IOException e) {
            api.logging().logToError("Error saving file: " + e.getMessage());
        }
        return false;
    }

    private static String secureFile(String fileName, Path outputDirPath) {
        File destinationDir = new File(outputDirPath.toString());

        String fakeRootPath = System.getenv("SystemDrive") != null ? 
            System.getenv("SystemDrive") : 
            FileSystems.getDefault().getSeparator();
            
        File untrustedFile = new File(fakeRootPath + fileName);

        try {
            File trustedFile = new File(destinationDir.getCanonicalPath() +
                    untrustedFile.toPath().normalize().toString()
                            .replace(fakeRootPath, FileSystems.getDefault().getSeparator()));

            if (trustedFile.getCanonicalPath().startsWith(destinationDir.getCanonicalPath())) {
                Utilities.createDirectoriesIfNotExist(trustedFile.getParentFile().toPath());
                return trustedFile.toString();
            } else {
                api.logging().logToError("Path traversal attempt prevented");
            }
        } catch (IOException e) {
            api.logging().logToError("Error securing file path: " + e.getMessage());
        }
        
        return getTempDirPath(outputDirPath).toString();
    }

    private static Path getTempDirPath(Path outputDirPath) {
        return outputDirPath.resolve("tmp");
    }
}
