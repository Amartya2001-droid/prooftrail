package dev.prooftrail.e2e;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.openqa.selenium.json.Json;

class DemoScenarioTest {
    @Test
    void pythonDemoCompletesBothTasksAndLeavesLedgerValid() throws Exception {
        String output = runPython("demo/agent_team_scenario.py");
        assertTrue(output.contains("Ledger valid after the runs: True"));
        assertTrue(output.contains("Runs recorded: 2"));
        assertTrue(output.contains("verify_project: verdict clean"));
        assertTrue(output.contains("build_dispute_case: verdict clean"));
        assertTrue(output.contains("rewrote most of the document"));
        assertTrue(output.contains("deterministic template text"));
        assertTrue(output.contains("not proof of AI"));
    }

    @SuppressWarnings("unchecked")
    static Map<String, String> scenarioText() throws Exception {
        // Load the actual demo constants: no duplicated/stubbed scenario fixture.
        String result = runPython("-c", "import json,runpy; d=runpy.run_path('demo/agent_team_scenario.py'); "
                + "print(json.dumps({k.lower(): d[k] for k in ('V1','V2','V3')}))");
        return new Json().toType(result, Map.class);
    }

    private static String runPython(String... arguments) throws Exception {
        var command = new java.util.ArrayList<String>();
        command.add(BrowserTest.env("PYTHON_EXECUTABLE", "python3"));
        command.addAll(java.util.List.of(arguments));
        Path output = Files.createTempFile("prooftrail-demo-", ".log");
        Process process = null;
        try {
            process = new ProcessBuilder(command)
                    .directory(Path.of(System.getProperty("e2e.projectRoot")).normalize().toFile())
                    .redirectErrorStream(true).redirectOutput(output.toFile()).start();
            assertTrue(process.waitFor(180, TimeUnit.SECONDS), "Demo exceeded 180-second limit");
            String text = Files.readString(output);
            assertEquals(0, process.exitValue(), "Demo failed: " + text);
            return text;
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly().waitFor();
            Files.deleteIfExists(output);
        }
    }
}
