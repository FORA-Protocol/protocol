Fixtures for remark-example.test.mjs. Every shape here is one the plugin must REFUSE,
kept in a file rather than in a string so the rejection is proved against a real read.

An empty region — markers with nothing between them:

<!-- fora:empty-region -->
```text
// fora:example emptyfixture
// fora:/example emptyfixture
```

An anchor that appears twice, so neither block is the one a page would get:

<!-- fora:twice-fixture -->
```text
first
```

<!-- fora:twice-fixture -->
```text
second
```
