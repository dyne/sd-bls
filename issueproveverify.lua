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

--A = keygen()
--sha256 = HASH.new('sha256')
TOTAL = 160
STEP = 10

-- Issuer's keyring hardcoded 0x0 seed
A = {sk = BIG.new(sha256(OCTET.zero(32)))}
A.pk = G2*A.sk

-- some functions are in common.lua

TOTAL = TOTAL + STEP -- off by one fix
printerr "issuance "
local ISSUANCE_T = { }
local fakes
for i=10,TOTAL,STEP do
  fakes = generate_fake_claims(i)
  printerr(i.." ")
  local start = os.clock()
  CLAIMS, REVOCS = issuer_sign(A.sk, fakes)
  table.insert(ISSUANCE_T, os.clock() - start)
end
collectgarbage'collect'
collectgarbage'collect'

printerr '\n'
printerr 'proof '
local PROOF_T = { }
for i=10,TOTAL,STEP do
  local disclose = { }
  local c = 1
  for k,v in pairs(CLAIMS) do
    table.insert(disclose, k)
    if c > i then break end
    c = c + 1
  end
  printerr(i.." ")
  local start = os.clock()
  PROOFS = holder_prove(CLAIMS, disclose)
  table.insert(PROOF_T, os.clock() - start)
end
collectgarbage'collect'
collectgarbage'collect'

printerr '\n'
printerr 'verification '
local VERIF_T = { }
for i=10,TOTAL,STEP do
  local c = 1
  local start = os.clock()
  for k,v in pairs(PROOFS) do
    assert( verify_proof(A.pk, v) )
    if c > i then break end
    c = c + 1
  end
  printerr(i.." ")
  table.insert(VERIF_T, os.clock() - start)
end
collectgarbage'collect'
collectgarbage'collect'

print("CLAIMS \t ISSUE \t PROVE \t VERIFY")
for i=1,(TOTAL/STEP),1 do
  write(i*STEP)
  write(' \t ')
  write(ISSUANCE_T[i])
  write(' \t ')
  write(PROOF_T[i])
  write(' \t ')
  write(VERIF_T[i])
  write('\n')
end

--   print(i..' \t\t '..ISSUANCE_T[i]..' \t\t '..PROOF_T[i])
-- end
