# SecureStore PHP library

This repository/package houses a PHP implementation of the cross-platform, language-agnostic [SecureStore secrets specification](https://neosmart.net/SecureStore). In particular, this library may be used for interacting with [SecureStore](https://github.com/neosmart/securestore-rs) secrets containers, providing an easy-to-use and idiomatic interface for loading SecureStore containers and decrypting/retrieving secrets from within your existing PHP code.

## Usage

_This PHP library is largely intended to be used alongside one of the SecureStore cli companion apps, used to create SecureStore values and manage (add/remove/update) the secrets stored therein. In this example, we'll be using the [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) cli utility to create a new store._

### Creating a secrets vault

Typical SecureStore usage begins by creating a new SecureStore "vault" (an encrypted secrets container) that will store the credentials (usually both usernames and passwords) that your app will need. Begin by compiling or downloading and installing a copy of [`ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient), the SecureStore companion cli.

While you can compile it yourself or manually download [pre-built binaries for your platform](https://github.com/neosmart/securestore-rs/releases), you might find it easiest to just install it with `npm`:

```bash
~> npm install --global ssclient
```

after which you can proceed with the following steps:

```bash
~> mkdir secure/
~> cd secure/
~> ssclient create --export-key secrets.key
Password: ************
Confirm Password: ************

# Now you can use `ssclient -p` with your password or
# `ssclient -k secrets.key` to encrypt/decrypt with
# the same keys.
```

### Adding secrets

Secrets may be added with your password or the equivalent encryption key file, and may be specified in-line as arguments to `ssclient` or more securely at a prompt by omitting the value when calling `ssclient create`:

```bash
# ssclient defaults to password-based decryption:
~> ssclient set aws:s3:accessId AKIAV4EXAMPLE7QWERT
Password: *********
```

similarly:

```bash
# Use `-k secrets.key` to load the encryption key and
# skip the prompt for the vault password:
~> ssclient -k secrets.key set aws:s3:accessKey
Value: v1Lp9X7mN2B5vR8zQ4tW1eY6uI0oP3aS5dF7gH9j
```

### Retrieving secrets

Secrets can be retrieved [at the commandline with `ssclient`](https://github.com/neosmart/securestore-rs/tree/master/ssclient) or programmatically with a SecureStore library [for your development language or framework of choice](https://neosmart.net/SecureStore).

This library contains the PHP implementation of the SecureStore protocol. The implementation is fully contained within the single `SecureStore.php` file and also published to packagist for use with `composer` – use whichever option you are most comfortable with.

```sh
composer add neosmart/securestore
```

```php
// require_once("SecureStore.php");
// or
// require __DIR__ . '/vendor/autoload.php';

use NeoSmart\SecureStore\SecretsManager;

// Load a vault using the decryption key file
$sm = SecretsManager::loadWithKeyFile('secure/secrets.json', 'secure/secrets.key');

// List all secrets
$allKeys = $sm->keys();

// Retrieve and decrypt secrets
$accessId  = $sm->get('aws:s3:accessId');
$accessKey = $sm->get('aws:s3:accessKey');

// Continue to use them as you normally would
```

While it is **strongly recommended** to only load secrets programmatically via the encryption key, an alternative `SecretsManager::loadWithPassword("path/to/secrets.json", "your-password")` interface is also available (this can be used if you're developing an interactive tool using SecureStore, for example).

# API overview

The `SecureStore` library provides a high-level interface for decrypting and accessing secrets stored in SecureStore v3 vaults.

### `NeoSmart\SecureStore\SecretsManager`
The primary class used to load vaults and retrieve decrypted secrets.

| Method | Description |
|:---|:---|
| `static loadWithKeyFile(string $path, string $keyPath): self` | A convenience method to load and decrypt a vault using SecureStore key file. |
| `static loadWithPassword(string $path, string $password): self` | A convenience method to load and decrypt a vault with a password. |
| `static load(string $path, KeySource $keySource): self` | Loads a vault using a pre-configured `KeySource` object. |
| `get(string $name): ?string` | Retrieves and decrypts a specific secret by its key name. Returns `null` if the secret does not exist. |
| `keys(): array` | Returns an array containing the names of all secrets available in the loaded vault. |

---

### `NeoSmart\SecureStore\KeySource`
An abstraction layer used to define the source of the decryption key (either a user-provided password or a cryptographic master key).

| Method | Description |
|:---|:---|
| `static fromFile(string $path): self` | Loads a decryption key from a file. Supports raw binary or ASCII-armored (PEM-style) SecureStore formats. |
| `static fromPassword(string $password): self` | Initializes a key source using a password. The decryption key will be derived per the SecureStore v3 spec. |
| `static fromKey(array\|string $key): self` | Loads a decryption key from a raw string or an array of bytes. |
