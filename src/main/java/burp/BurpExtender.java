package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.menu.Menu;
import burp.api.montoya.ui.menu.MenuItem;
import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.TaskRepository;
import burp.core.ScannerBuilder;
import burp.utils.Utilities;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider {
    private final MontoyaApi api;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static final TaskRepository taskRepository = TaskRepository.getInstance();
    private static final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    public static final String EXTENSION_NAME = "JS Miner-NG";
    private static final String EXTENSION_VERSION = "2.0";
    private int taskCount = 0;

    public BurpExtender(MontoyaApi api) {
        this.api = api;
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize components
        TaskRepository.setApi(api);
        Utilities.setApi(api);  // Add this line
        
        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            taskRepository.destroy();
            api.logging().logToOutput("Sending shutdown signal to terminate any running threads...");
            executorServiceManager.getExecutorService().shutdownNow();
            api.logging().logToOutput("Extension was unloaded");
            api.logging().logToOutput("=================================================");
        });
        
        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(this);
        
        // Register HTTP handler for passive scanning
        api.http().registerHttpHandler(new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                return RequestToBeSentAction.continueWith(requestToBeSent);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (extensionConfig.isPassiveEnabled()) {
                    doPassiveScan(responseReceived);
                }
                return ResponseReceivedAction.continueWith(responseReceived);
            }
        });

        api.logging().logToOutput("Loading " + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        api.logging().logToOutput("Original Author: Mina M. Edwar");
        api.logging().logToOutput("Forked by: pedro (slicingmelon)");
        
        loadExtensionConfig();
    }

    @Override
    public List<MenuItem> provideMenuItems(ContextMenuEvent event) {
        if (event.selectedRequestResponses().isEmpty()) {
            return List.of();
        }
        
        List<MenuItem> menuItems = new ArrayList<>();
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();
        
        // Main menu item
        menuItems.add(MenuItem.builder()
            .text("Run JS Auto-Mine (check everything)")
            .action(e -> runAutoMine(selectedMessages))
            .build());
        
        // Add submenus
        menuItems.add(Menu.builder()
            .text("Scans")
            .menuItems(createScanMenuItems(selectedMessages))
            .build());
            
        menuItems.add(Menu.builder()
            .text("Config")
            .menuItems(createConfigMenuItems())
            .build());
            
        menuItems.add(Menu.builder()
            .text("Log")
            .menuItems(createLogMenuItems())
            .build());
            
        return menuItems;
    }

    private List<MenuItem> createLogMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        menuItems.add(MenuItem.builder()
            .text("Clear Log")
            .action(e -> taskRepository.clearTasks())
            .build());
        return menuItems;
    }

    private void runAutoMine(List<HttpRequestResponse> messages) {
        new Thread(() -> {
            long ts = Instant.now().toEpochMilli();
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0]))
                .runAllPassiveScans()
                .taskId(++taskCount)
                .timeStamp(ts)
                .build();
            scannerBuilder.runScans();
        }).start();
    }

    private void doPassiveScan(HttpResponseReceived response) {
        executorServiceManager.getExecutorService().submit(() -> {
            long ts = Instant.now().toEpochMilli();
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api)
                .withHttpResponse(response)
                .runAllPassiveScans()
                .timeStamp(ts)
                .build();
            scannerBuilder.runScans();
        });
    }

    private List<MenuItem> createScanMenuItems(List<HttpRequestResponse> messages) {
        List<MenuItem> menuItems = new ArrayList<>();
        
        addScanMenuItem(menuItems, "Run all passive scans", messages, 
            b -> b.runAllPassiveScans().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(menuItems, "JS source mapper (active)", messages, 
            ScannerBuilder.Builder::scanSourceMapper);
        addScanMenuItem(menuItems, "Secrets", messages, ScannerBuilder.Builder::scanSecrets);
        addScanMenuItem(menuItems, "Dependency Confusion", messages, ScannerBuilder.Builder::scanDependencyConfusion);
        addScanMenuItem(menuItems, "SubDomains", messages, ScannerBuilder.Builder::scanSubdomains);
        addScanMenuItem(menuItems, "Cloud URLs", messages, ScannerBuilder.Builder::scanCloudURLs);
        addScanMenuItem(menuItems, "Inline B64 JS Source Maps", messages, 
            b -> b.scanSourceMapper().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(menuItems, "Dump Static Files", messages, 
            b -> b.dumpStaticFiles().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(menuItems, "API Endpoints Finder", messages, ScannerBuilder.Builder::scanEndpoints);
        
        return menuItems;
    }

    private void addScanMenuItem(List<MenuItem> menuItems, String text, List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        menuItems.add(MenuItem.builder()
            .text(text)
            .action(e -> runScan(messages, scanType))
            .build());
    }

    private void runScan(List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        executorServiceManager.getExecutorService().submit(() -> {
            ScannerBuilder scannerBuilder = scanType.apply(new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0])))
                .taskId(++taskCount)
                .build();
            scannerBuilder.runScans();
        });
    }

    private List<MenuItem> createConfigMenuItems() {
        List<MenuItem> menuItems = new ArrayList<>();
        
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.loggingConfigMenuItemText())
            .action(e -> {
                extensionConfig.toggleLogging();
                updateExtensionConfig();
            })
            .build());
            
        menuItems.add(MenuItem.builder()
            .text(extensionConfig.passiveConfigMenuItemText())
            .action(e -> {
                extensionConfig.togglePassiveScans();
                updateExtensionConfig();
            })
            .build());
            
        return menuItems;
    }

    private void updateExtensionConfig() {
        api.persistence().preferences().setString(SETTING_VERBOSE_LOGGING, 
            String.valueOf(extensionConfig.isVerboseLogging()));
        api.persistence().preferences().setString(SETTING_BURP_PASSIVE, 
            String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    private void loadExtensionConfig() {
        String verboseLogging = api.persistence().preferences().getString(SETTING_VERBOSE_LOGGING);
        if (verboseLogging != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(verboseLogging));
        }

        String passiveEnabled = api.persistence().preferences().getString(SETTING_BURP_PASSIVE);
        if (passiveEnabled != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(passiveEnabled));
        }
    }
}