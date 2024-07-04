G1 = ECP.generator()
G2 = ECP2.generator()
-- H =  hash to point function to ECP1
HG1 = ECP.hashtopoint
Miller = PAIR.ate

function keygen()
-- δ = r.O
-- γ = δ.G2
   local sk = INT.random()
   return { sk = sk,
            pk = G2 * sk }
end
function sign(sk, msg)
-- σ = δ * ( H(m)*G1 )
   return HG1(msg) * sk
end

function verify(pk, msg, sig)
-- e(γ,H(m)) == e(G2,σ)
   return(
	  Miller(pk, HG1(msg))
	  ==
    Miller(G2, sig)
   )
end
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

-- Issuer signs claims
SIGNED_CLAIMS = { }
REVOCATIONS = { }
for k,v in pairs(CLAIMS) do
   local rev = BIG.random()
   local id = k..'='..v
   local sig = sign(A.sk, id) + sign(rev, id)
   SIGNED_CLAIMS[id] = { sig, G2 * rev }
   REVOCATIONS['HolderID/'..id] = rev
end
sha256 = HASH.new('sha256')

function holder_prove(signed_claims, disclosures)
  local res = { }
  local tri
  for m,v in pairs(signed_claims) do
    local sig = v[1] -- naked issuer's sig
    local revG2 = v[2]
    local claim = strtok(m, '=')
    -- assert(tri == BIG.new(sha256:process(
    --                        (PAIR.ate(A.pk, G1*er)^rev):octet()
    -- )))
    if array_contains(disclosures, claim[1]) then
      table.insert(res, {
                     id = m,
                     s = sig,
                     r = revG2:to_zcash()
      })
    end
  end
  return res
end

function revocation_contains(revocations, claim)
  local res   = false -- store here result for constant time operations
  local rev = revocations[claim.id]
  if rev then
    if claim.r == (G2*rev):to_zcash() then
      res = true
    end
  end
  return res
end

-- disclose = { 'name', 'gender', 'above_18' }
local torevoke = {
  'HolderID/born_in=Napoli',
  'HolderID/gender=male',
  'HolderID/nationality=italian'}
local revocations = {}
for _,v in pairs(torevoke) do
  local k = strtok(v,'/')[2]
  revocations[k] = REVOCATIONS[v]
end

DISCLOSE = { 'name', 'gender', 'above_18' }
CREDENTIAL_PROOF = holder_prove(SIGNED_CLAIMS, DISCLOSE)
-- show encoded claims example
print(JSON.encode({
          credential_proof = CREDENTIAL_PROOF,
          verifier = 'IssuerID',
          revocations = revocations
}))
I.schema({proof=CREDENTIAL_PROOF,
          rev=revocations})
-- relying party verifies credentials
-- downloads PK of IssuerID from DID
for _,proof in pairs(CREDENTIAL_PROOF) do
  assert( verify(ECP2.from_zcash(proof.r) + A.pk,
                 proof.id, proof.s) )
  if proof.id == 'gender=male' then
    assert(revocation_contains(revocations, proof), "Not revoked: "..proof.id)
  else
    assert(not revocation_contains(revocations, proof), "Revoked: "..proof.id)
  end
end

warn('random proof.s')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.s = ECP.random() -- FUZZ
  assert( not verify(ECP2.from_zcash(proof.r) + A.pk,
                     proof.id, proof.s) )
  if proof.id == 'gender=male' then
    assert(revocation_contains(revocations, proof), "Not revoked: "..proof.id)
  else
    assert(not revocation_contains(revocations, proof), "Revoked: "..proof.id)
  end
end

warn('random proof.r')
for _,proof in pairs(CREDENTIAL_PROOF) do
  proof.r = ECP2.random():to_zcash() -- FUZZ
  assert( not verify(ECP2.from_zcash(proof.r) + A.pk,
                     proof.id, proof.s) )
  assert(not revocation_contains(revocations, proof), "Revoked: "..proof.id)
end

warn('random A.pk')
for _,proof in pairs(CREDENTIAL_PROOF) do
  assert( not verify(ECP2.from_zcash(proof.r) + ECP2.random(),
                     proof.id, proof.s) )
  -- if proof.id == 'gender=male' then
  --   assert(revocation_contains(revocations, proof), "Not revoked: "..proof.id)
  -- else
    assert(not revocation_contains(revocations, proof), "Revoked: "..proof.id)
    -- end
end
