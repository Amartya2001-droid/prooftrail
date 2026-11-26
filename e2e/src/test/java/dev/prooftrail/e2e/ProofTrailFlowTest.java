package dev.prooftrail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WindowType;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

class ProofTrailFlowTest extends BrowserTest {
    @Test
    void dashboardShowsAccountProjectsAndAgentGuidance() {
        assertEquals("ProofTrail", driver.getTitle());
        assertEquals("ProofTrail", driver.findElement(By.tagName("h1")).getText());
        textEquals("auth-state", "Not signed in.");
        registerAndSignIn("Dashboard reviewer");
        nav("projects");
        textEquals("project-list", "No projects yet. Create one above.");
        assertTrue(driver.findElement(By.id("form-create-project")).isDisplayed());
        nav("agents");
        textContains("status", "Pick a project");
        for (String specialist : List.of("Trailboss", "Verity", "Sleuth", "Mapper", "Scribe")) {
            assertTrue(text("agent-roster").contains(specialist));
        }
    }

    @Test
    void createsProjectUploadsTextAndVerifiesItsHistory() {
        registerAndSignIn("Project reviewer");
        String title = "Provenance review " + UUID.randomUUID();
        createProject(title);
        upload("Original draft", "A signed original draft. Its history is recorded.", 1);
        nav("verify");
        textContains("verify-valid", "Ledger valid:");
        textContains("verify-chain", "sha256:");
        assertFalse(text("verify-chain").contains("A signed original draft."),
                "Verification view must expose hashes rather than document content");
        nav("projects");
        wait.until(d -> projectRow(title) != null && projectRow(title).getText().contains("1 versions"));
    }

    @Test
    void demoScenarioRunsBothAgentTasksWithRealFindingsAndActivity() throws Exception {
        Map<String, String> scenario = DemoScenarioTest.scenarioText();
        String writerTab = driver.getWindowHandle();
        registerAndSignIn("Amartya (E2E)");
        driver.switchTo().newWindow(WindowType.TAB);
        String editorTab = driver.getWindowHandle();
        driver.get(baseUrl);
        Account editor = registerAndSignIn("Priya (E2E)");
        driver.switchTo().window(writerTab);

        String title = "Disputed announcement " + UUID.randomUUID();
        createProject(title);
        nav("projects");
        clickProjectControl(title, "Collaborators");
        textContains("collaborator-project", title);
        fill("collaborator-username", editor.username());
        clickCss("#form-add-collaborator button[type=submit]");
        textContains("collaborator-list", "Priya (E2E)");
        selectProject(title);
        upload("v1", scenario.get("v1"), 1);

        driver.switchTo().window(editorTab);
        selectProject(title);
        upload("v2", scenario.get("v2"), 2);
        nav("declarations");
        wait.until(d -> d.findElements(By.cssSelector("#declare-version option")).size() == 2);
        new Select(driver.findElement(By.id("declare-version"))).selectByIndex(1);
        fill("declare-tool", "ChatGPT");
        fill("declare-summary", "Draft the demo paragraph (synthetic E2E declaration)");
        clickCss("#form-declare button[type=submit]");
        textContains("declaration-list", "ChatGPT");
        upload("v3", scenario.get("v3"), 3);

        nav("agents");
        textContains("agent-project", "Project:");
        textEquals("agent-runs-list", "None.");
        click("button-run-verify");
        textContains("agent-report-verdict", "verify_project — verdict: clean");
        textContains("agent-report-findings", "rewrote most of the document");
        textContains("agent-report-findings", "no AI-use declaration");
        textContains("agent-report-findings", "cannot prove how");
        for (String specialist : List.of("Verity", "Sleuth", "Scribe")) {
            assertTrue(text("agent-report-summaries").contains(specialist));
        }
        click("button-run-dispute");
        textContains("agent-report-verdict", "build_dispute_case — verdict: clean");
        textContains("agent-report-summaries", "Mapper");
        textContains("agent-report-findings", "2 ai-assisted");
        wait.until(d -> d.findElements(By.cssSelector("#agent-runs-list > li")).size() == 2);
        assertTrue(text("agent-runs-list").contains("verify_project"));
        assertTrue(text("agent-runs-list").contains("build_dispute_case"));
        assertTrue(text("agent-runs-list").contains("finished"));
        click("button-activity-refresh");
        textContains("activity-list", "Agent run");
        textContains("activity-list", "agent_run_finished");
        assertFalse(text("activity-list").contains("undefined"));
        nav("verify");
        textContains("verify-valid", "Ledger valid:");
    }

    @Test
    void activityFeedPollsNewEventsFromAnotherTabAndRefreshesManually() {
        Account account = registerAndSignIn("Activity reviewer");
        String title = "Activity project " + UUID.randomUUID();
        createProject(title);
        upload("v1", "The original activity feed draft.", 1);
        nav("agents");
        textContains("activity-list", "upload");
        assertEquals(1, eventCount("upload"));
        assertEquals(0, eventCount("edit"));
        String feedTab = driver.getWindowHandle();

        driver.switchTo().newWindow(WindowType.TAB);
        driver.get(baseUrl);
        signIn(account);
        selectProject(title);
        upload("v2", "The original activity feed draft. An update from another tab.", 2);
        driver.close();
        driver.switchTo().window(feedTab);
        // No refresh click here: prove the real 10-second poll, with a bounded wait.
        new WebDriverWait(driver, Duration.ofSeconds(35)).until(d -> eventCount("edit") == 1);
        click("button-activity-refresh");
        wait.until(d -> eventCount("upload") == 1 && eventCount("edit") == 1);
        List<String> times = activityLines().stream()
                .map(line -> line.split(" — ", 2)[0]).toList();
        for (int i = 1; i < times.size(); i++) {
            assertTrue(times.get(i - 1).compareTo(times.get(i)) >= 0, "Activity must be newest first");
        }
        assertFalse(text("activity-list").contains("undefined"));
    }

    @Test
    void dashboardGuidedDemoCompletesAndResumesWithoutDuplicateWrites() throws Exception {
        nav("projects");
        click("button-guided-demo");
        textContains("status", "Sign in or register");
        registerAndSignIn("Guided demo reviewer");
        nav("projects");
        click("button-guided-demo");
        wait.until(d -> d.findElement(By.id("guided-demo-panel")).isDisplayed());
        wait.until(d -> d.findElement(By.id("button-run-verify")).getDomProperty("disabled").equals("true"));
        textContains("guided-demo-status", "Demo complete");
        for (String step : List.of("sample", "verify", "dispute", "ledger")) {
            assertEquals("done", driver.findElement(By.id("demo-step-" + step)).getDomAttribute("data-state"));
        }
        textContains("agent-report-summaries", "Mapper");
        String originalProject = text("agent-project");
        String originalRuns = text("agent-runs-list");
        textContains("agent-report-findings", "rewrote most of the document");
        textContains("activity-list", "Agent run");
        ((org.openqa.selenium.JavascriptExecutor) driver).executeScript("window.scrollTo(0, 0)");
        java.nio.file.Path screenshots = java.nio.file.Path.of(System.getProperty("e2e.outputDir"));
        java.nio.file.Files.createDirectories(screenshots);
        java.nio.file.Files.write(screenshots.resolve("guided-demo.png"),
            ((org.openqa.selenium.TakesScreenshot) driver).getScreenshotAs(org.openqa.selenium.OutputType.BYTES));
        assertEquals(2, driver.findElements(By.cssSelector("#agent-runs-list > li")).size());
        nav("projects");
        wait.until(d -> d.findElement(By.id("project-list")).getText().contains("Demo — Robotics"));
        assertEquals(1, driver.findElements(By.cssSelector("#project-list > li")).size());
        driver.navigate().refresh();
        nav("projects");
        click("button-guided-demo");
        textContains("guided-demo-status", "Demo complete");
        assertEquals(2, driver.findElements(By.cssSelector("#agent-runs-list > li")).size());
        nav("verify");
        textContains("verify-valid", "Ledger valid:");
        assertEquals(3, driver.findElements(By.cssSelector("#verify-chain > li")).size());
        nav("projects");
        wait.until(d -> d.findElement(By.id("project-list")).getText().contains("Demo — Robotics"));
        assertEquals(1, driver.findElements(By.cssSelector("#project-list > li")).size());
        nav("versions");
        upload("Owner edit", "My own edited sample announcement. Preserve this version.", 4);
        nav("projects");
        click("button-guided-demo");
        textContains("guided-demo-status", "sample has been edited");
        assertFalse(driver.findElement(By.id("button-resume-demo")).isDisplayed());
        assertTrue(driver.findElement(By.id("button-fresh-demo")).isEnabled());
        textEquals("agent-runs-list", originalRuns);
        assertEquals("paused", driver.findElement(By.id("demo-step-sample")).getDomAttribute("data-state"));
        click("button-fresh-demo");
        textContains("guided-demo-status", "Demo complete");
        assertNotEquals(originalProject, text("agent-project"));
        assertEquals(2, driver.findElements(By.cssSelector("#agent-runs-list > li")).size());
        nav("projects");
        wait.until(d -> d.findElements(By.cssSelector("#project-list > li")).size() == 2);
        // Projects are newest-first. Re-find the older row inside the bounded wait.
        wait.until(d -> {
            var rows = d.findElements(By.cssSelector("#project-list > li"));
            if (rows.size() != 2) return false;
            rows.get(1).findElement(By.xpath(".//button[text()='Select']")).click();
            return true;
        });
        nav("agents");
        textEquals("agent-project", originalProject);
        textEquals("agent-runs-list", originalRuns);
        nav("verify");
        // The previous project's Verify view may still be visible until GET completes.
        wait.until(d -> d.findElements(By.cssSelector("#verify-chain > li")).size() == 4
                && d.findElement(By.id("verify-chain")).getText().contains("Owner edit"));
        textContains("verify-valid", "Ledger valid:");
        nav("projects");
        wait.until(d -> d.findElements(By.cssSelector("#project-list > li")).size() == 2);
        String independentTitle = "Independent project " + UUID.randomUUID();
        fill("project-title", independentTitle);
        clickCss("#form-create-project button[type=submit]");
        wait.until(d -> projectRow(independentTitle));
        // Navigate directly: do not click Select, which has its own reset path.
        nav("agents");
        textEquals("agent-runs-list", "None.");
        assertFalse(driver.findElement(By.id("guided-demo-panel")).isDisplayed(),
                "A different project must not show the sample's completed checklist");
    }

    @Test
    void versionsResetAndPagingOwnTheirDelayedResponses() {
        registerAndSignIn("Versions race reviewer");
        String title = "Versions race " + UUID.randomUUID();
        var js = (org.openqa.selenium.JavascriptExecutor) driver;
        driver.manage().timeouts().scriptTimeout(Duration.ofSeconds(120));
        // Seed real signed versions via the real API, not mocked responses.
        Map<?, ?> fixture = (Map<?, ?>) js.executeAsyncScript("""
            const title = arguments[0], done = arguments[arguments.length - 1];
            (async () => {
              const post = async (path, body) => {
                const response = await fetch(path, {method: 'POST', headers: {
                  'Content-Type': 'application/json',
                  Authorization: 'Bearer ' + sessionStorage.getItem('pt-token')
                }, body: JSON.stringify(body)});
                if (!response.ok) throw new Error('Fixture HTTP ' + response.status);
                return response.json();
              };
              const project = await post('/api/projects', {title});
              for (let i = 0; i < 52; i++) {
                await post('/api/projects/' + project.project_id + '/uploads', {
                  content_base64: btoa('Draft ' + i + '.'), label: 'v' + i
                });
              }
              done({project_id: project.project_id});
            })().catch(error => done({error: error.message}));
            """, title);
        assertFalse(fixture.containsKey("error"), "Real API fixture setup must succeed");
        selectProject(title);
        wait.until(d -> d.findElements(By.cssSelector("#version-list > li")).size() == 50);
        js.executeScript("""
            window.__versionsFetch = window.fetch;
            window.__versionRequests = [];
            const prefix = '/api/projects/' + arguments[0] + '/versions?';
            window.fetch = (...args) => {
              const actual = window.__versionsFetch.apply(window, args);
              if (!String(args[0]).startsWith(prefix)) return actual;
              const request = {ready: false};
              const gate = new Promise(resolve => request.release = resolve);
              window.__versionRequests.push(request);
              return actual.then(response => {
                request.ready = true;
                return gate.then(() => response);
              });
            };
            """, fixture.get("project_id"));
        try {
            js.executeScript("window.__olderVersions = loadVersions(); window.__newerVersions = loadVersions();");
            wait.until(d -> Boolean.TRUE.equals(js.executeScript(
                    "return __versionRequests.length === 2 && __versionRequests.every(r => r.ready)")));
            // Deliver the newer real response first, then the obsolete response.
            js.executeScript("__versionRequests[1].release()");
            assertNull(js.executeAsyncScript("const done=arguments[0]; __newerVersions.then(() => done(null), e => done(e.message))"));
            assertEquals(50, driver.findElements(By.cssSelector("#version-list > li")).size());
            js.executeScript("__versionRequests[0].release()");
            assertNull(js.executeAsyncScript("const done=arguments[0]; __olderVersions.then(() => done(null), e => done(e.message))"));
            assertEquals(50, driver.findElements(By.cssSelector("#version-list > li")).size(),
                    "Obsolete reset must not append a duplicate first page");

            js.executeScript("__versionRequests = []; window.__nextVersions = loadVersions(false); window.__duplicateNext = loadVersions(false);");
            wait.until(d -> Boolean.TRUE.equals(js.executeScript(
                    "return __versionRequests.length > 0 && __versionRequests.every(r => r.ready)")));
            assertEquals(1, ((Number) js.executeScript("return __versionRequests.length")).intValue(),
                    "Repeated next-page requests must coalesce while pending");
            assertFalse(driver.findElement(By.id("button-versions-more")).isEnabled());
            js.executeScript("__versionRequests[0].release()");
            assertNull(js.executeAsyncScript("const done=arguments[0]; Promise.all([__nextVersions,__duplicateNext]).then(() => done(null), e => done(e.message))"));
            assertEquals(52, driver.findElements(By.cssSelector("#version-list > li")).size());
            assertEquals(52, ((Number) js.executeScript(
                    "return new Set(Array.from(document.querySelectorAll('#version-list > li'), row => row.textContent)).size")).intValue());
            assertFalse(driver.findElement(By.id("button-versions-more")).isDisplayed());
        } finally {
            js.executeScript("for (const r of window.__versionRequests || []) r.release(); window.fetch = window.__versionsFetch;");
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> activityLines() {
        // The poll replaces <li> nodes. Read one DOM snapshot instead of keeping
        // WebElements that can become stale between remote getText() calls.
        return (List<String>) ((org.openqa.selenium.JavascriptExecutor) driver).executeScript(
                "return Array.from(document.querySelectorAll('#activity-list > li'), row => row.innerText)");
    }

    private int eventCount(String type) {
        return (int) activityLines().stream()
                .filter(line -> line.contains(" — " + type + " — ")).count();
    }
}
