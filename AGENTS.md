# Repository standing rules

1. Work on a branch. Open a pull request for every change. Never push directly to main.
2. Tests must pass before a PR is opened. If the repo has no tests, add a smoke test for what you changed.
3. Never commit secrets, API keys or credentials. Never invent credentials, licences or metrics.
4. Keep the README honest: what works, what is live, and the live URL.
5. At the end of the day, create (if it does not exist) the issue "10-day agent program — daily log" and post your report as a comment in this format:

   ```markdown
   ## Day N — <repo>
   Did:
   - <completed work, each with PR/commit link>
   Blocked on: <anything needing Amartya>
   Will do tomorrow:
   - <planned work>
   Live status: <URL or "not live yet — blocked by …">
   ```

   Then stop. Do not start new work after the report.

## Day 1 scope (Nov 11, 2026 task brief)

Triage only: get oriented, get CI green, fix what's already open, and set up
reporting. No new features. Prepare deployment documentation, but do not deploy.
Do not change the agent-team showcase (Trailboss, Verity, Sleuth, Mapper, Scribe);
that is separately handled Day 3 work. Running the existing full test suite is
part of triage and includes its existing agent tests.
