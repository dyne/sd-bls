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
TOTAL = 160
STEP = 10
N_PROOFS = 1

fakes = generate_fake_claims(N_PROOFS)
CLAIMS, REVOC, T = test_many_issuance(fakes)
PROOFS, T = test_many_proofs(N_PROOFS, CLAIMS)

printerr''
printerr "revocation "
local REVOCS_T = { }
-- I.warn({revocs = REVOC, proofs = PROOFS})
local claim_id = REVOC[1][1]

for i=10,TOTAL,STEP do
  local FAKEREVOCS = { }
  table.insert(FAKEREVOCS, REVOC[1])
  for n=1,i,1 do
    table.insert(FAKEREVOCS,{ claim_id, BIG.modrand(ECP.order()) })
  end
  -- I.warn({revocs = i, size = table_size(FAKEREVOCS)})
  -- I.schema(FAKEREVOCS)
  printerr(i.." ")
  T = test_many_revocs(i, FAKEREVOCS, PROOFS)
  table.insert(REVOCS_T, T)

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
