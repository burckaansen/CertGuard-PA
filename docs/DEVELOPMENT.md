# Development Notes

## Baseline rule

Do not patch old generated zip packages as the development source.

The source of truth is:

```text
src/certguard_agent.py
installer/Install-CertGuard-PA.ps1
```

Future builds should continue from this clean repository structure.

## Service model

Use `sc.exe` service creation. Do not reintroduce pywin32.

## Versioning

- v1.0.0 = clean baseline
- patch = bugfix
- minor = feature
- major = architecture change
