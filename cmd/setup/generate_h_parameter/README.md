# H Parameter Generator for Baby Jubjub

This utility generates the **H parameter** for the DVP (Designated Verifier Proof) system using the **Nothing Up My Sleeve (NUMS)** methodology. The H parameter is a base point on the Baby Jubjub elliptic curve used in Pedersen commitments.

## What is H?

H is a generator point on the Baby Jubjub twisted Edwards curve, obtained by:
1. Starting with a seed value (1)
2. Hashing repeatedly until finding a valid x-coordinate on the curve
3. Computing the corresponding y-coordinate
4. Clearing the cofactor by multiplying by 8 (to ensure the point is in the prime-order subgroup)

## Why NUMS?

For Pedersen commitments `Commit(v, r) = v*G + r*H`, security requires that **nobody knows the discrete log relationship** between G and H. If someone knew `k` such that `H = k*G`, they could open commitments to arbitrary values, breaking the binding property.

The NUMS approach ensures:
- **No trapdoor** — you can't secretly pick an H where you know the discrete log to G
- **Publicly verifiable** — anyone can reproduce this exact computation starting from seed=1
- **Deterministic** — the SHA256 chain makes it computationally infeasible to have "aimed" for a specific point

## How the Search Works

Not every x-value has a valid y on the curve. When computing `y² = (1 - ax²) / (1 - dx²)`, the result might not be a quadratic residue (no square root exists in the field).

Statistically, about **50% of field elements** are quadratic residues, so on average a valid point is found in ~2 iterations. The loop is effectively guaranteed to terminate almost instantly — hitting 1000 failures would have probability ~2⁻¹⁰⁰⁰.

## Running the Generator

From the repository root:
```bash
cd cmd/setup/generate_h_parameter
go run main.go
```

## Output

The utility will:
1. Search for a valid Baby Jubjub point by hashing
2. Clear the cofactor (multiply by 8)
3. Verify the point using a gnark zero-knowledge circuit
4. Output the final H coordinates

Example output:
```
=====================================
Baby Jubjub H Parameter Generator
=====================================

🔍 Searching for valid H point...
✅ Found valid point H:
   Hx = 18088494987768362437108104365733457390180002882080199252891584927105189390906
   Hy = 18851452430177667536696249872672129346900883028423229527829953506995373114404

🔄 Clearing cofactor (multiplying by 8)...
✅ Cofactor-cleared H:
   Hx = 18088494987768362437108104365733457390180002882080199252891584927105189390906
   Hy = 18851452430177667536696249872672129346900883028423229527829953506995373114404

🔐 Verifying point using gnark circuit...
✅ Circuit verification successful!

=====================================
Final H Parameter (Cofactor-Cleared)
=====================================
Hx = "18088494987768362437108104365733457390180002882080199252891584927105189390906"
Hy = "18851452430177667536696249972672129346900883028423229527829953506995373114404"

✅ H parameter generation complete!
```

## Using the Generated H Parameter

The generated H coordinates should be placed in `primitives/GroupMath.go`:
```go
var (
    Hx = "18088494987768362437108104365733457390180002882080199252891584927105189390906"
    Hy = "18851452430177667536696249872672129346900883028423229527829953506995373114404"
    // ...
    H = twistededwards.Point{X: Hx, Y: Hy}
)
```

## Why Run This Once?

This is a **one-time setup** operation because:
- The H parameter is deterministic (always produces the same result from seed=1)
- It's a public parameter used system-wide
- Changing H would invalidate all existing commitments

## Security Note

The H parameter is generated using a deterministic, publicly-verifiable process (hash-to-curve) to ensure:
1. **Nobody knows the discrete log** of H with respect to G (the other base point)
2. **It's verifiable** — anyone can re-run this script and get the same result
3. **It's in the prime-order subgroup** (after cofactor clearing)

## Dependencies

- gnark (for circuit verification)
- gnark-crypto (for elliptic curve operations)
- Standard Go crypto libraries (SHA-256)