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

-- A = keygen()
-- sha256 = HASH.new('sha256')
TOTAL = 50000
STEP =  5000
N_PROOFS = 1

-- Issuer's keyring hardcoded 0x0 seed
A = {sk = BIG.new(sha256(OCTET.zero(32)))}
A.pk = G2*A.sk

fakes = generate_fake_claims(1)
CLAIMS, REVOC = issuer_sign(A.sk, fakes)

local disclose = { }
for k,v in pairs(CLAIMS) do
  table.insert(disclose, k)
end
I.warn('disclosing: '..#disclose)
PROOFS = holder_prove(CLAIMS, disclose)

printerr''
printerr "revocation "
local REVOCS_T = { }
-- I.warn({revocs = REVOC, proofs = PROOFS})
local claim_id
for k,v in pairs(REVOC) do
  claim_id = k
end

for i=10,TOTAL,STEP do

  -- generation takes most time in this test
  local FAKEREVOCS = { }
  for n=1,i,1 do
    FAKEREVOCS[claim_id] = BIG.modrand(ECP.order())
  end
  FAKEREVOCS[claim_id] = REVOC[claim_id]

  printerr(i.." ")
  local start = os.clock()
  local found = 0
  for k,v in ipairs(PROOFS) do
    if verify_proof(A.pk, v) then
      if revocation_contains(FAKEREVOCS, v) then
        found = found + 1
      end
    end
  end
  assert(found == 1)
  table.insert(REVOCS_T, os.clock() - start)
  collectgarbage'collect'
  collectgarbage'collect'
end


print("REVOCATIONS \t TIME")
for i=1,(TOTAL/STEP),1 do
  write(i*STEP)
  write(' \t\t ')
  write(REVOCS_T[i])
  write('\n')
end
