-- SD-BLS common functions for the proof of concept in Zenroom
--
-- Copyright (C) 2024 Dyne.org foundation designed, written and
-- maintained by Denis Roio <jaromil@dyne.org>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public
-- License along with this program.  If not, see
-- <https://www.gnu.org/licenses/>.

CONF.output.encoding = { fun = get_encoding_function'url64',
                         name = 'url64' }
G1 = ECP.generator()
G2 = ECP2.generator()
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


-- POC high level API

function issuer_sign_kv(sk, claims)
  local signed = { }
  local revs= { }
  for k,v in pairs(claims) do
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

function issuer_sign(sk, claims)
  local signed = { }
  local revs= { }
  for k,v in pairs(claims) do
    local rSK = BIG.random()
    local m = k..'='..v
    local o = { }
    o.r = (G2 * rSK):to_zcash()
    o.H = sha256(m..o.r)
    o.s = sign(A.sk, o.H..o.r) + sign(rSK, o.H..o.r)
    signed[m] = o
    revs[o.H] = rSK
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
    if array_contains(disclosures, m) then
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

-- used in POC with k=v credentials
function holder_prove_kv(signed_claims, disclosures)
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

function anon_revocation_contains(rev, proof)
  local res   = false -- store here result for constant time operations
  local r = proof.r
  -- assert(revocations[h])
  -- TODO: for some reason revocations[proof.H] doesn't works
  for _,v in ipairs(rev) do
      res = r == (G2*v):to_zcash()
  end
  return res
end


function revocation_contains(rev, proof)
  local res   = false -- store here result for constant time operations
  local h = proof.H
  local r = proof.r
  -- assert(revocations[h])
  -- TODO: for some reason revocations[proof.H] doesn't works
  local f = rev[h]
  if f then
      res = r == (G2*f):to_zcash()
  end
  return res
end

-- Benchmark functions

function generate_fake_claims(num)
  local cls = { }
  for i=1,num do
    cls[OCTET.random(8)] = OCTET.random(8)
  end
  return cls
end

function test_many_revocs(num, revocs, proofs)
  local start = os.clock()
  local c = 0
  local found = 0
  for k,v in ipairs(proofs) do
    local pk = ECP2.from_zcash(v.r)
    if verify(pk + A.pk, v.id, v.s) then
      found = revocation_contains(revocs, v)
    end
    c = c + 1
    if c == num then break end
  end
  assert(found == 1)
  return os.clock() - start
end
