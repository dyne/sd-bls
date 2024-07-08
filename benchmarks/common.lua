-- common.lua
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
   local sk = INT.modrand(ECP.order())
   return { sk = sk,
			pk = G2 * sk }
end
function sign(sk, msg)
-- σ = δ * ( H(m)*G1 )
   return HG1(msg) * sk
end

A = keygen()
-- sha256 = HASH.new('sha256')

function verify(pk, msg, sig)
-- e(γ,H(m)) == e(G2,σ)
   return(
	  Miller(pk, HG1(msg))
	  ==
    Miller(G2, sig)
   )
end

function generate_fake_claims(num)
  local cls = { }
  for i=1,num do
    cls[OCTET.random(8)] = OCTET.random(8)
  end
  return cls
end

function test_many_issuance(fakes)
  local start = os.clock()
  local revocs = { }
  local claims = { }
  for k,v in pairs(fakes) do
    local claim = k..v
    local rev = BIG.modrand(ECP.order())
    local sig = sign(A.sk, claim) + sign(rev, claim)
    table.insert(claims, {
                   c = claim,
                   s = sig,
                   r2 = (G2 * rev):to_zcash()
    })
    table.insert(revocs, { claim, rev })
  end
  return claims, revocs, os.clock() - start
end

function test_many_proofs(num, creds)
  local start = os.clock()
  proofs = { }
  local c = 0
  for k,v in ipairs(creds) do
    local sig = v.s -- naked issuer's sig
    local revG2 = v.r2
    table.insert(proofs, {
                   id = v.c,
                   s = v.s,
                   r = v.r2
    })
    c = c + 1
    if c == num then break end
  end
  return proofs, os.clock() - start
end

function test_many_verifs(num, proofs)
  local start = os.clock()
  local c = 0
  for k,v in ipairs(proofs) do
    local sig = v.s
    local pk = ECP2.from_zcash(v.r)
    assert( verify(pk + A.pk, v.id, v.s) )
    c = c + 1
    if c == num then break end
  end
  return os.clock() - start
end


function revocation_contains(revocations, proof)
  local res   = 0 -- store here result for constant time operations
  for k,v in ipairs(revocations) do
    if v[1] == proof.id then
      local rev = v[2]
      if -- addendum of proof.p is equal to revG2
        proof.r == (G2*rev):to_zcash()
      then
        res = 1
      end
    end
  end
  return res
end

function test_many_revocs(num, revocs, proofs)
  local start = os.clock()
  local c = 0
  local found = 0
  for k,v in ipairs(proofs) do
    local pk = ECP2.from_zcash(v.r)
    assert( verify(pk + A.pk, v.id, v.s) )
    found = revocation_contains(revocs, v)
    c = c + 1
    if c == num then break end
  end
  assert(found == 1)
  return os.clock() - start
end
