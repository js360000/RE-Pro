# RE-Pro Plugins

RE-Pro can load extra analyzers from this directory automatically.

Supported local plugin patterns:

- A module-level `register_analyzers()` function returning one or more analyzer instances or classes.
- A module-level `ANALYZERS` export containing one or more analyzer instances or classes.
- One or more `Analyzer` subclasses defined directly in the module.

The engine loads `*.py` files from this directory at startup. Files beginning with `_` are ignored.

Minimal example:

```python
from re_pro.analyzers.base import Analyzer


class DemoAnalyzer(Analyzer):
    name = "Demo plugin analyzer"

    def analyze(self, context, report) -> None:
        if context.target.suffix.lower() == ".xyz":
            report.add_framework("Custom XYZ format")


def register_analyzers():
    return [DemoAnalyzer()]
```

For packaged/distributed plugins, Python entry points are also supported under the group `re_pro.analyzers`.
