# Operations Guide

## Palo Alto API key

```text
https://<PA-HOST>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>
```

Copy the value inside `<key>...</key>`.

## Basic flow

1. Configure win-acme
2. Verify PFX generation
3. Run setup wizard
4. TestApi
5. TestWacs
6. CompareCert
7. PolicyDeploy

## Policy logic

- Import if certificate missing (optional)
- Import if expiring
- Import if local newer/different
