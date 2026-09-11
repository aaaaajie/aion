# jwt_tool bundle

This release exposes the non-interactive AION adapter at `bin/jwt_tool`.
The adapter follows the JWT parsing, tampering, signing, verification and
bounded key-testing workflow of [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)
v2.3.0, pinned to commit `3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b`.

It is deliberately invoked through typed AION tool arguments so it cannot
open an interactive menu or accept arbitrary command-line options.
