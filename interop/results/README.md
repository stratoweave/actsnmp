# interop/results

Output of `interop/run-interop.sh`. Nothing here
is committed except this README and `.gitignore`.

| File | Content |
|---|---|
| `LATEST.md` | summary of the last run: one row per phase (PASS/FAIL, run time inside the bench lock, lock wait, key numbers) and the clicheck section table |
| `<phase>.log` | whole output of a phase: `build`, `library`, `cli`, `agent`, `notify`, `trapd` |
| `clicheck.md` | report of `interop/clicheck.sh` (failures with diffs, documented differences) |
| `agentcheck.md` | report of `interop/agentcheck.sh` against our agent |
| `receiver.out`, `receiver.err`, `agent4.err`, `agent6.err` | what our receiver (`actsnmp trapd --canon`) and agents printed during the run |
| `bin/actsnmp` | the CLI binary the run used (copied after the build phase) |
