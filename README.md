# Apple BIN Device Structure Analyzer (MVP)

### Contributing BIN samples and pattern findings

If you have any BIN dumps from ACE / ICE ROMs, you are very welcome to test them with this tool.

This project is still experimental. The goal is to analyze many different dumps from real repair cases and look for repeated structures or patterns. A single BIN file usually does not tell the whole story, but comparing multiple dumps from different symptoms may help us understand what changes between good, bad, donor, original, unlocked, or modified ROM contents.

The analyzer does not rely on fixed offsets. From the dumps tested so far, the same logical data can appear at different physical locations. Because of that, the tool tries to detect structures by nearby markers and field relationships instead of hardcoded addresses.
https://binlabkris-eng.github.io/Ace_bin_analyzer/
Examples of detected structures:

```text
Apple Inc. → iPhone / iPad / Macintosh / ACE1P → model or platform code

## Run

```bash
cd apple-bin-analyzer
npm install
npm run dev
```

## Tests

```bash
npm test
```

