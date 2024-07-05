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

function issuer_sign(claims)
  local signed = { }
  local revs= { }
  for k,v in pairs(CLAIMS) do
    local rSK = BIG.random()
    local m = k..'='..v
    local o = { }
    o.r = (G2 * rSK):to_zcash()
    o.H = sha256(m..o.r)
    o.s = sign(A.sk, o.H..o.r) + sign(rSK, o.H..o.r)
    signed[m] = o
    revs['HolderID/'..m] = rSK
  end
  return signed, revs
end

function issuer_revoke(revocations, torevoke)
  local revs = { }
  for _,v in pairs(torevoke) do
    -- revokers will keep a database of HolderIDs with revocations; the
    -- privacy of such databases can be enhanced by not holding values
    -- in such a database.
    local m = strtok(v,'/')[2]
    local r = (G2*revocations[v]):to_zcash()
    local h = sha256(m..r)
    -- I.warn(r)
    revs[h] = revocations[v]
  end
  return revs
end

function holder_prove(signed_claims, disclosures)
  local res = { }
  for m,v in pairs(signed_claims) do
    local claim = strtok(m, '=')
    if array_contains(disclosures, claim[1]) then
      local obj = {
        m = m,
        H = v.H,
        r = v.r
      }
      local tSK = BIG.random()
      obj.s = v.s + sign(tSK, obj.H..obj.r)
      obj.t = os.date()
      obj.p = (G2*tSK):to_zcash()
      obj.c = sign(tSK, obj.H .. obj.r .. obj.s:octet() .. obj.t)
      table.insert(res, obj)
    end
  end
  return res
end

function verify_proof(APK, proof)
  local res = true and
    verify(ECP2.from_zcash(proof.p),
           (proof.H .. proof.r .. proof.s:octet() .. proof.t),
           proof.c)
  return res and verify(ECP2.from_zcash(proof.r) +
                        ECP2.from_zcash(proof.p) +
                        APK, proof.H..proof.r, proof.s)
end

function revocation_contains(revocations, proof)
  local res   = false -- store here result for constant time operations
  local h = proof.H
  -- assert(revocations[h])
  -- TODO: for some reason revocations[proof.H] doesn't works
  for k,v in pairs(revocations) do
    if k==proof.H and proof.r == (G2*v):to_zcash() then
      res = true
    end
  end
  return res
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

SIGNED_CLAIMS, REVOCATIONS = issuer_sign(CLAIMS)

local TOREVOKE = {
  'HolderID/born_in=Napoli',
  'HolderID/gender=male',
  'HolderID/nationality=italian'}

REVOKED = issuer_revoke(REVOCATIONS, TOREVOKE)

DISCLOSE = { 'name', 'gender', 'above_18' }

CREDENTIAL_PROOF = holder_prove(SIGNED_CLAIMS, DISCLOSE)

for _,proof in pairs(CREDENTIAL_PROOF) do
  assert(verify_proof(A.pk, proof) )
end

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
