# scrypt

This package is built directly on Node's native `crypto.scrypt`, dependency-free, timing-safe, stable, and fully typed. It's made for real-world apps that need secure defaults and clean DX out of the box, without pointless config or [runtime issues](https://github.com/ranisalt/node-argon2/issues/421). Simple API, predictable behavior, works everywhere a [supported](https://github.com/rccyx/scrypt/blob/main/.github/workflows/test.yml#L13) Node runs.

## install

```bash
pnpm add @rccyx/scrypt
```

## usage

### Basic Example (Synchronous)

```ts
import { hashSync, verifySync } from "@rccyx/scrypt";

// Hash a password
const hashed = hashSync({ plaintext: "password123" });
// Returns: "salt:key" (hex-encoded, e.g., "a1b2c3d4...:e5f6g7h8...")

// Verify a password
const isValid = verifySync({ hash: hashed, plaintext: "password123" });
// Returns: true
```

### Basic Example (Asynchronous)

```ts
import { hash, verify } from "@rccyx/scrypt";

// Hash a password
const hashed = await hash({ plaintext: "password123" });

// Verify a password
const isValid = await verify({ hash: hashed, plaintext: "password123" });
```

### Custom Key Length

Each hash uses a random 16-byte salt and a default 64-byte derived key. You can customize the key length:

```ts
import { hashSync } from "@rccyx/scrypt";

// Use a longer key for enhanced security
const hashed = hashSync({
  plaintext: "password123",
  keyLength: 256
});
```

Valid key lengths: `64` (default) | `128` | `256` | `512` | `1024` bytes.

## API

### `hash(options)`

Asynchronously hashes a plaintext password using scrypt.

**Parameters:**
- `options.plaintext` (string): The plaintext password to hash
- `options.keyLength` (optional, KeyLength): The length of the derived key in bytes (default: `64`)

**Returns:** `Promise<string>` - A hash string in the format `"salt:key"` (hex-encoded)

**Example:**
```ts
const hashString = await hash({ plaintext: "mySecurePassword" });
const hashString256 = await hash({ plaintext: "mySecurePassword", keyLength: 256 });
```

### `hashSync(options)`

Synchronously hashes a plaintext password using scrypt.

**Parameters:**
- `options.plaintext` (string): The plaintext password to hash
- `options.keyLength` (optional, KeyLength): The length of the derived key in bytes (default: `64`)

**Returns:** `string` - A hash string in the format `"salt:key"` (hex-encoded)

**Example:**
```ts
const hashString = hashSync({ plaintext: "mySecurePassword" });
const hashString256 = hashSync({ plaintext: "mySecurePassword", keyLength: 256 });
```

### `verify(options)`

Asynchronously verifies a plaintext password against a stored hash. Uses timing-safe comparison to prevent timing attacks.

**Parameters:**
- `options.hash` (string): The stored hash string to compare against
- `options.plaintext` (string): The plaintext password to verify

**Returns:** `Promise<boolean>` - `true` if the password matches, `false` otherwise

**Example:**
```ts
const isValid = await verify({
  hash: storedHash,
  plaintext: userInput
});
if (isValid) {
  console.log("Password is correct");
}
```

### `verifySync(options)`

Synchronously verifies a plaintext password against a stored hash. Uses timing-safe comparison to prevent timing attacks.

**Parameters:**
- `options.hash` (string): The stored hash string to compare against
- `options.plaintext` (string): The plaintext password to verify

**Returns:** `boolean` - `true` if the password matches, `false` otherwise

**Example:**
```ts
const isValid = verifySync({
  hash: storedHash,
  plaintext: userInput
});
if (isValid) {
  console.log("Password is correct");
}
```

### `KeyLength`

Type definition for valid key lengths: `64 | 128 | 256 | 512 | 1024`

## Hash Format

Each hash is stored as `salt:key` in hexadecimal format, where:
- **salt**: A random 16-byte value (32 hex characters)
- **key**: The derived key from scrypt (default 64 bytes = 128 hex characters)

Example: `"a1b2c3d4e5f6...32chars...:e7f8g9h0...128chars..."`


## License

MIT © [@rccyx](https://rccyx.com)

