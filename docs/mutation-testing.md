# Mutation testing with turtles

The first campaign is intentionally bounded to `src/server/top_origin.mbt` and
`src/browser/capabilities.mbt`. It tests the new MoonBit policy decisions; it does
not measure the whole library or mutate JavaScript FFI bodies. Mocked browser
tests separately exercise the capability API bridge.

## Reproduce

Use MoonBit `0.1.20260920` and turtles commit
`4d9baaa258c695e803a487283076e979e2c260ba` (`turtles --version`: `0.3.0`):

```sh
moon install https://github.com/f4ah6o/turtles.git cmd/turtles --rev 4d9baaa258c695e803a487283076e979e2c260ba
moon update
turtles --dir . --target js --list
turtles --dir . --target js --jobs 2 --fail-under 100 --json .turtles/report.json
```

`turtles.toml` selects both files and explicitly enables function-body mutations,
alongside comparison, boolean, arithmetic, literal and condition mutations. The
body operator checks that deleting a policy's behavior cannot pass unnoticed.

Turtles runs a baseline check and repeated baseline tests, then checks/tests each
mutant in a temporary workspace. It does not change the working source files.
Reports and survivor diffs are written under the automatically ignored
`.turtles/` directory.

## Observed result

On 2026-10-02, the documented campaign completed with 19 active mutations: 15
killed, 4 unviable, and no survivors or timeouts. All four unviable mutations
changed string concatenation in a way rejected by the type checker. The viable
score was 100% (15/15).

| File | Killed | Unviable | Survived | Timed out |
| --- | ---: | ---: | ---: | ---: |
| src/server/top_origin.mbt | 7 | 4 | 0 | 0 |
| src/browser/capabilities.mbt | 8 | 0 | 0 | 0 |

The full JavaScript release check also passed with 120 tests.

## CI gate and interpretation

The separate `Mutation testing` workflow runs on PRs and main pushes. It installs
the exact tested turtles revision, uses `--target js`, requires a 100% viable
mutation score, and verifies that each policy file has at least one killed mutant.
The latter check prevents an empty or entirely unviable campaign from passing.
The report is retained as the `turtles-js-report` artifact, including when the
campaign fails.

`KILLED` means tests rejected a compilable mutation; `SURVIVED` means they did not.
`UNVIABLE` means the compiler rejected the mutation and excludes it from the
score. `TIMEOUT` counts against the score. A 100% score for these files is not a
whole-library coverage claim and does not establish real-browser compatibility.

When expanding the campaign, analyze survivors before adding a threshold or a
skip: add missing behavioral cases for real gaps, simplify genuinely redundant
decisions where behavior is unchanged, and document equivalent mutants.
