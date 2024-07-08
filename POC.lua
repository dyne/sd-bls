
-- Issuer's keyring hardcoded 0x0 seed
A = {sk = BIG.new(sha256(OCTET.zero(32)))}
A.pk = G2*A.sk
-- Holder sends claims to issuer and proves them
CLAIMS = {
  name = "Pasqualino",
  surname = "Frafuso",
  nickname = "Settebellezze",
  born_in = "Napoli",
  gender = "male",
  above_18 = 'true',
  nationality = "italian"
}

SIGNED_CLAIMS, REVOCATIONS = issuer_sign(A.sk, CLAIMS)

local TOREVOKE = {
  'HolderID/born_in=Napoli',
  'HolderID/gender=male',
  'HolderID/nationality=italian'}

REVOKED = issuer_revoke(REVOCATIONS, TOREVOKE)

DISCLOSE = { 'name', 'gender', 'above_18' }

CREDENTIAL_PROOF = holder_prove_kv(SIGNED_CLAIMS, DISCLOSE)

for _,proof in pairs(CREDENTIAL_PROOF) do
  assert(verify_proof(A.pk, proof) )
end

warn('revoked gender=male')
for _,proof in pairs(CREDENTIAL_PROOF) do
  local H = sha256(proof.m..proof.r)
  assert(H == proof.H, "Invalid proof hash")
  assert(verify_proof(A.pk, proof) )
  if proof.m == 'gender=male' then
    assert(revocation_contains(REVOKED, proof), "Not revoked: "..proof.m)
  else
    assert(not revocation_contains(REVOKED, proof), "Revoked: "..proof.m)
  end
end

warn('random proof.s')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.s = ECP.random() -- FUZZ
  assert( not verify_proof(A.pk, proof) )
  if proof.m == 'gender=male' then
    assert(revocation_contains(REVOKED, proof), "Not revoked: "..proof.m)
  else
    assert(not revocation_contains(REVOKED, proof), "Revoked: "..proof.m)
  end
end

warn('random proof.p')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.p = ECP2.random():to_zcash() -- FUZZ
  assert(not verify_proof(A.pk, proof) )
end

warn('random proof.t')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.t = OCTET.random(32)
  assert(not verify_proof(A.pk, proof) )
end

warn('random proof.c')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.c = sign(BIG.random(), OCTET.random(32))
  assert(not verify_proof(A.pk, proof) )
end

warn('random proof.r')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.r = ECP2.random():to_zcash() -- FUZZ
  assert(not verify_proof(A.pk, proof) )
  assert(not revocation_contains(REVOKED, proof), "Revoked: "..proof.m)
end

warn('random A.pk')
for _,proof in pairs(CREDENTIAL_PROOF) do
  assert(not verify_proof(ECP2.random(), proof) )
  assert(not revocation_contains(REVOKED, proof), "Revoked: "..proof.m)
end
