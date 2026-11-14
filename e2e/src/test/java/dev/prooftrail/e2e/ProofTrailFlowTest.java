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
        wait.until(d -> projectRow(title)).findElement(By.xpath(".//button[text()='Collaborators']")).click();
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
        List<String> times = driver.findElements(By.cssSelector("#activity-list > li")).stream()
                .map(row -> row.getText().split(" — ", 2)[0]).toList();
        for (int i = 1; i < times.size(); i++) {
            assertTrue(times.get(i - 1).compareTo(times.get(i)) >= 0, "Activity must be newest first");
        }
        assertFalse(text("activity-list").contains("undefined"));
    }

    private int eventCount(String type) {
        return (int) driver.findElements(By.cssSelector("#activity-list > li")).stream()
                .filter(row -> row.getText().contains(" — " + type + " — ")).count();
    }
}
