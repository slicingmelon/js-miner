package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.menu.MenuItem;
import burp.api.montoya.ui.menu.Menu;
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
        api.extension().setName(EXTENSION_NAME);
        
        // Initialize components
        TaskRepository.setApi(api);
        Utilities.setApi(api);
        
        // Register context menu
        api.userInterface().registerContextMenuItemsProvider(this);
        
        // Register unloading handler
        api.extension().registerUnloadingHandler(() -> {
            taskRepository.destroy();
            api.logging().logToOutput("Sending shutdown signal to terminate any running threads...");
            executorServiceManager.getExecutorService().shutdownNow();
            api.logging().logToOutput("Extension was unloaded");
            api.logging().logToOutput("=================================================");
        });
        
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
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty() && event.selectedRequestResponses().isEmpty()) {
            return null;
        }

        List<Component> menuItems = new ArrayList<>();
        List<HttpRequestResponse> selectedMessages = event.selectedRequestResponses();

        // Main menu item
        JMenuItem autoMineItem = new JMenuItem("Run JS Auto-Mine (check everything)");
        autoMineItem.addActionListener(e -> runAutoMine(selectedMessages));
        menuItems.add(autoMineItem);

        // Scans submenu
        JMenu scansMenu = new JMenu("Scans");
        createScanMenuItems(selectedMessages).forEach(scansMenu::add);
        menuItems.add(scansMenu);

        // Config submenu
        JMenu configMenu = new JMenu("Config");
        createConfigMenuItems().forEach(configMenu::add);
        menuItems.add(configMenu);

        // Log submenu
        JMenu logMenu = new JMenu("Log");
        createLogMenuItems().forEach(logMenu::add);
        menuItems.add(logMenu);

        return menuItems;
    }

    private List<JMenuItem> createScanMenuItems(List<HttpRequestResponse> messages) {
        List<JMenuItem> items = new ArrayList<>();
        
        addScanMenuItem(items, "Run all passive scans", messages, 
            b -> b.runAllPassiveScans().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(items, "JS source mapper (active)", messages, 
            ScannerBuilder.Builder::scanSourceMapper);
        addScanMenuItem(items, "Secrets", messages, 
            ScannerBuilder.Builder::scanSecrets);
        addScanMenuItem(items, "Dependency Confusion", messages, 
            ScannerBuilder.Builder::scanDependencyConfusion);
        addScanMenuItem(items, "SubDomains", messages, 
            ScannerBuilder.Builder::scanSubdomains);
        addScanMenuItem(items, "Cloud URLs", messages, 
            ScannerBuilder.Builder::scanCloudURLs);
        addScanMenuItem(items, "Inline B64 JS Source Maps", messages, 
            b -> b.scanSourceMapper().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(items, "Dump Static Files", messages, 
            b -> b.dumpStaticFiles().timeStamp(Instant.now().toEpochMilli()));
        addScanMenuItem(items, "API Endpoints Finder", messages, 
            ScannerBuilder.Builder::scanEndpoints);
        
        return items;
    }

    private void addScanMenuItem(List<JMenuItem> items, String text, List<HttpRequestResponse> messages, 
            Function<ScannerBuilder.Builder, ScannerBuilder.Builder> scanType) {
        JMenuItem item = new JMenuItem(text);
        item.addActionListener(e -> runScan(messages, scanType));
        items.add(item);
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

    private List<JMenuItem> createConfigMenuItems() {
        List<JMenuItem> items = new ArrayList<>();
        
        JMenuItem loggingItem = new JMenuItem(extensionConfig.loggingConfigMenuItemText());
        loggingItem.addActionListener(e -> {
            extensionConfig.toggleLogging();
            updateExtensionConfig();
        });
        items.add(loggingItem);

        JMenuItem passiveItem = new JMenuItem(extensionConfig.passiveConfigMenuItemText());
        passiveItem.addActionListener(e -> {
            extensionConfig.togglePassiveScans();
            updateExtensionConfig();
        });
        items.add(passiveItem);

        return items;
    }

    private List<JMenuItem> createLogMenuItems() {
        List<JMenuItem> items = new ArrayList<>();
        JMenuItem clearLogItem = new JMenuItem("Clear Log");
        clearLogItem.addActionListener(e -> taskRepository.clearTasks());
        items.add(clearLogItem);
        return items;
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

    private void runAutoMine(List<HttpRequestResponse> messages) {
        executorServiceManager.getExecutorService().submit(() -> {
            ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(api, messages.toArray(new HttpRequestResponse[0]))
                .runAllPassiveScans()
                .taskId(++taskCount)
                .timeStamp(Instant.now().toEpochMilli())
                .build();
            scannerBuilder.runScans();
        });
    }
}