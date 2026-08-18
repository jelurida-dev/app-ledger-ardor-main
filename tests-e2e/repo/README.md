# Local Maven repository

The Ardor jars the end to end tests build against, copied from the internal
`ardor-library` project (Ardor 2.6.3). They are built from publicly released Ardor
source and carry the Jelurida Public License.

| Artifact                        | What it provides                                                                                       |
|---------------------------------|--------------------------------------------------------------------------------------------------------|
| `com.jelurida:ardorlib`         | the Ardor node classes, including the Ledger bridge (`com.jelurida.ardor.integration.wallet.ledger.*`) |
| `com.jelurida:ardor-tests`      | the node test framework (`nxt.BlockchainTest` and friends)                                             |
| `purejavahidapi:purejavahidapi` | a Jelurida-patched HID library that `ardorlib` needs and Maven Central does not carry                  |

Every other dependency resolves from Maven Central.

To move to a newer Ardor release, copy the new version directories over from
`ardor-library/repo/` and bump the version in `../build.gradle`.
