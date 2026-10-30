# NiralScript

NiralScript is the zero-dependency reactive language compiler behind
[Niral](https://github.com/Zyora-Dev/niral). It parses, type-checks and compiles
`.nrs` sources with no runtime dependencies — Node 22+ and the standard library
only.

See [NIRALSCRIPT.md](NIRALSCRIPT.md) for the language reference.

## Use

```sh
npx nrs check src/app.nrs
npx nrs compile src/app.nrs --out dist/app.mjs
```

```js
import { parseNiralScript } from "niralscript";
import { checkNiralScript } from "niralscript/check";
import { compileNiralScript } from "niralscript/compile";
```

## Note

Niral vendors this compiler directly, so the framework keeps its zero-dependency
guarantee. This repository is the standalone source of record.

MIT © ZyoraLabs
