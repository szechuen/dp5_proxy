## Back of the envelope parametrized cost estimate for multy-plase
## presence protocol. Phases: check revoke, (get session key), presence-hint, full-presence, presence-data

## Number of users in system:
Nusers = 10000
Nfriends = 100
Fonline = 0.3
Rrevoke = 0.1 ## A revocation event every 10 days
Rpresent = 16 * 60 ## 16 hours online, once a minute

Hsize = 20
Psize = 32
TSsize = 4 ## Timestamp size
Psize = 16 ## Plaintext size

## Phase 1 -- check-revoke-DB
## This is a database that maps: userID (20 bytes H(pubkey)) -> Timestamp (4 bytes)

p1DBsize = Nusers * (Hsize + TSsize)
p1Rate = (Fonline * Nusers) * Nfriends

## Phase 2 -- get-session-key-DB (optional if revocation)
## Database of: H(shared-key) -> E(session-key)

p2DBsize = (Nfriends * Nusers) * (Hsize + Psize)
p2Rate = (Fonline * Nusers) * Rrevoke

## Phase 3 -- presence-hint-DB
## Database: m-bit bloom filter

m = 10000000
k = 3
p3DBsize = (m / 8 + 1)
p3Rate = (Fonline * Nusers) * Rpresent * (Nfriends * k)

## Phase 4 -- full-presence-DB
## Database of H(session-key | T)

p4DBsize = (Nusers * Fonline) * Hsize
p4Rate = (Fonline * Nusers) * Rpresent * (Nfriends * Fonline)

## Phase 5 -- presence-data-DB
## Database of H(session-key | T) -> E(plaintext)

p4DBsize = (Nusers * Fonline) * Hsize
p4Rate = (Fonline * Nusers) * Rpresent * (Nfriends * Fonline) * (Hsize + Psize)
