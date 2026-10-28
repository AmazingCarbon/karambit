# `karambit secure`: move `.env` files into the vault

Back to [README](../README.md).


`karambit secure [path]` (alias `karambit eat`) moves a project's plaintext `.env`,
`.env.local` and `.env.<mode>` files into the vault, in one command:

1. Preview (names only, never values): which variables look secret, where each goes,
   git warnings (tracked, in history, not ignored). `--dry-run` stops here; agents may run it.
2. Each secret is stored as `<project>/<VAR>` at `--access` (default `agents-touch`).
   Existing entries with the same name are kept, not overwritten. The project name is the
   folder name (or `--name`). If the vault already has entries under `<project>/` that this
   directory's `.env.schema` doesn't refer to (another project with the same folder name),
   `secure` stops before storing anything and asks for `--name`.
3. Each original file is also archived whole as `<project>/_archive/<n>/<file>`
   (Only me · Touch ID), so rebuild restores it byte for byte. `<n>` is a new number every
   run; an archive is never overwritten. `rebuild` restores the newest archive of each file
   and still reads the older unnumbered names (`<project>/_archive/<file>`).
4. A value-free `.env.schema` is written (merged if one exists), and trusted (Touch ID).
   The trust also pins the `scripts` of the sibling `package.json` (see below).
5. Archives are decrypted and compared before any plaintext file is deleted. Each file is
   then renamed aside, read again and compared with what was archived. If you saved it
   while the prompts were open, it is kept (nothing is deleted) and `secure` stops; run it
   again to archive the newer version. A new `.env` saved after the check is a new file and is not touched.
6. `package.json` `dev`/`start`/`serve`/`test`/`build`/`preview` scripts get a
   `karambit run --` prefix (shown first; `--no-scripts` to skip). Bun projects get
   `env = false` in `bunfig.toml`, so Bun doesn't load `.env` itself.

Trusting the schema also records a digest of the `scripts` object of the `package.json`
next to it (a fixed marker if there is none). If those scripts change later, for example a
`dev` script is pointed at another command, the profile is `profile.untrusted` for agents,
and humans get the usual warning. Review the change, then run the `profile trust` subcommand.

After that, `npm run dev` works as before: `karambit run` reads `.env.schema`, injects
secrets through the usual policy, sets plain values, and redacts output. Variables that
are already set in your shell win over plain schema values, like dotenv.
Variables that make a program load code (`NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_*`, ...) are the
exception: `secure` warns and leaves them out of the schema (set them in your shell), and `run` refuses a schema
that sets one as a plain value, for humans too, because the schema is trusted automatically.
`karambit secure rebuild` writes the original files back (mode 0600; vault copies kept).

If a `.env` was ever committed, rotate those keys: deleting the file doesn't change git
history. Overwriting on an SSD is not secure erase either.

`.env.schema` uses varlock's @env-spec format, so existing varlock schemas mostly work:

```sh
# @defaultRequired=false
# ---
# @sensitive=false @type=port
PORT=3000
APP_URL=http://localhost:${PORT}
# @sensitive @docs(https://dashboard.stripe.com/apikeys)
STRIPE_SECRET_KEY=karambit(myapp/STRIPE_SECRET_KEY)
```

Supported: `KEY=value`, quotes, multi-line, `${VAR}` / `${VAR:-default}`, `@sensitive`,
`@required`, `@optional`, `@type=string|number|boolean|url|port|email|enum(...)`,
`@defaultRequired`, `@docs`. `karambit(ref)` takes any ref `run -e` accepts, including
a reference to a configured linked source. Other resolver functions (`op()`, `exec()`, ...), `$(...)` and object
literals are refused, not guessed; other decorators are ignored with a warning.

