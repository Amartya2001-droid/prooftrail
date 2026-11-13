package dev.prooftrail.e2e;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.AfterTestExecutionCallback;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.OutputType;
import org.openqa.selenium.TakesScreenshot;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

/** Real browser + real server. No intercepted requests or mocked agent responses. */
abstract class BrowserTest {
    protected WebDriver driver;
    protected WebDriverWait wait;
    protected String baseUrl;

    // Failure evidence is a screenshot only: no tokens, password values or page dumps.
    @RegisterExtension
    final AfterTestExecutionCallback screenshotOnFailure = context -> {
        if (context.getExecutionException().isPresent() && driver != null) {
            try {
                Path output = Path.of(System.getProperty("e2e.outputDir"));
                Files.createDirectories(output);
                Files.write(output.resolve(context.getRequiredTestMethod().getName() + ".png"),
                        ((TakesScreenshot) driver).getScreenshotAs(OutputType.BYTES));
            } catch (Exception ignored) {
                // A closed browser must not obscure the original failure.
            }
        }
    };

    @BeforeEach
    void startBrowser() {
        baseUrl = env("APP_BASE_URL", "http://127.0.0.1:8000").replaceAll("/+$", "");
        URI origin = URI.create(baseUrl);
        if (!("http".equals(origin.getScheme()) || "https".equals(origin.getScheme()))
                || origin.getHost() == null || origin.getUserInfo() != null
                || origin.getQuery() != null || origin.getFragment() != null
                || !(origin.getPath().isEmpty() || origin.getPath().equals("/"))) {
            throw new IllegalArgumentException("APP_BASE_URL must be an HTTP(S) origin without credentials");
        }
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--headless=new", "--window-size=1440,1100", "--disable-dev-shm-usage");
        // Optional for container environments; CI runners do not need this flag.
        if (Boolean.parseBoolean(env("CHROME_NO_SANDBOX", "false"))) {
            options.addArguments("--no-sandbox");
        }
        String binary = System.getenv("CHROME_BINARY");
        if (binary != null && !binary.isBlank()) options.setBinary(binary);
        String driverPath = System.getenv("CHROMEDRIVER_PATH");
        if (driverPath != null && !driverPath.isBlank()) {
            driver = new ChromeDriver(new ChromeDriverService.Builder()
                    .usingDriverExecutable(Path.of(driverPath).toFile()).build(), options);
        } else {
            driver = new ChromeDriver(options); // Selenium Manager resolves a compatible driver.
        }
        driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(60));
        wait = new WebDriverWait(driver, Duration.ofSeconds(120));
        wait.ignoring(org.openqa.selenium.StaleElementReferenceException.class);
        driver.get(baseUrl);
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("form-login")));
    }

    @AfterEach
    void stopBrowser() {
        if (driver != null) driver.quit();
    }

    protected record Account(String username, String password) {}

    protected Account registerAndSignIn(String name) {
        nav("auth");
        // Unique, disposable local test accounts; never a production credential.
        Account account = new Account("e2e_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16),
                UUID.randomUUID().toString() + "-Aa7!");
        fill("register-username", account.username());
        fill("register-name", name);
        fill("register-password", account.password());
        clickCss("#form-register button[type=submit]");
        textContains("status", "Registered.");
        signIn(account);
        return account;
    }

    protected void signIn(Account account) {
        nav("auth");
        fill("login-username", account.username());
        fill("login-password", account.password());
        clickCss("#form-login button[type=submit]");
        textEquals("auth-state", "Signed in.");
    }

    protected void nav(String section) {
        click("nav-" + section);
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("section-" + section)));
    }

    protected void createProject(String title) {
        nav("projects");
        fill("project-title", title);
        clickCss("#form-create-project button[type=submit]");
        textContains("status", "Project created.");
        wait.until(d -> projectRow(title));
        selectProject(title);
    }

    protected WebElement projectRow(String title) {
        return driver.findElements(By.cssSelector("#project-list > li")).stream()
                .filter(row -> row.getText().startsWith(title + " (")).findFirst().orElse(null);
    }

    protected void selectProject(String title) {
        nav("projects");
        WebElement row = wait.until(d -> projectRow(title));
        row.findElement(By.xpath(".//button[text()='Select']")).click();
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("section-versions")));
        textContains("versions-project", title);
    }

    protected void upload(String label, String text, int expectedVersions) {
        nav("versions");
        fill("upload-text-label", label);
        fill("upload-text", text);
        clickCss("#form-upload-text button[type=submit]");
        wait.until(d -> d.findElements(By.cssSelector("#version-list > li")).size() == expectedVersions
                && d.findElement(By.id("version-list")).getText().contains(label));
    }

    protected void fill(String id, String value) {
        WebElement input = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id(id)));
        input.clear();
        input.sendKeys(value);
    }

    protected void click(String id) {
        wait.until(ExpectedConditions.elementToBeClickable(By.id(id))).click();
    }

    protected void clickCss(String selector) {
        wait.until(ExpectedConditions.elementToBeClickable(By.cssSelector(selector))).click();
    }

    protected void textContains(String id, String text) {
        wait.until(ExpectedConditions.textToBePresentInElementLocated(By.id(id), text));
    }

    protected void textEquals(String id, String text) {
        wait.until(d -> d.findElement(By.id(id)).getText().equals(text));
    }

    protected String text(String id) { return driver.findElement(By.id(id)).getText(); }

    protected static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
