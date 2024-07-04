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

PVSS = require_once'crypto_pvss'
TOTAL = 100
STEP = 10

GEN = PVSS.set_generators()

SECRET = BIG.random()
-- sha256 = HASH.new('sha256')
USABLE_SECRET = sha256(GEN.G*SECRET)

function create_shares(total,quorum)
  local Ppk = { }
  local Psk = { }
  for i=1,total do
    local sk = PVSS.keygen()
    local pk = PVSS.sk2pk(GEN, sk)
    table.insert(Psk,sk)
    table.insert(Ppk,pk)
  end
  local start = os.clock()
  local shares = PVSS.create_shares(GEN, SECRET, Ppk, quorum, total, false)
  assert( PVSS.verify_shares(GEN, quorum, total, shares) )
  return Ppk, Psk, shares, os.clock() - start
end

function reconstruct_shares(Ppk, Psk, shares)
  local decrypted = { }
  local total = #shares.encrypted_shares
  local quorum = (total / 2) + 2
  local start = os.clock()
  assert(luatype(Ppk)=='table')
  assert(luatype(Psk)=='table')
  for i=1,quorum do
    table.insert(decrypted,
                 PVSS.decrypt_share(GEN, Psk[i], Ppk[i], shares))
  end
  local val, idx =
    PVSS.verify_decrypted_shares(GEN, decrypted)
  assert(
    sha256(PVSS.pooling_shares(val, idx, quorum))
    ==
    USABLE_SECRET
  )
  return os.clock() - start
end

local CREATE_T = { }
local RECONSTRUCT_T = { }
for i=STEP,TOTAL,STEP do
  printerr('shares ' ..i)
  local quorum = (i / 2)
  P_PK, P_SK, SHARES, T = create_shares(i, quorum)
  table.insert(CREATE_T, T)
  collectgarbage'collect'
  collectgarbage'collect'
  -- print(JSON.encode(P_SK))
  table.insert(RECONSTRUCT_T, reconstruct_shares(P_PK, P_SK, SHARES))
  collectgarbage'collect'
  collectgarbage'collect'
end

print("SHARES \t CREATE \t RECONSTRUCT")
for i=1,(TOTAL/STEP),1 do
  write(i*STEP)
  write(' \t ')
  write(CREATE_T[i])
  write(' \t ')
  write(RECONSTRUCT_T[i])
  write('\n')
end

-- print(JSON.encode(SHARES))
-- takes a list of PKS
-- t is the quorum
-- n is the number of participants
-- local total = #PARTICIPANTS_PK
-- local quorum = (total / 2 ) + 1

-- SHARES = PVSS.create_shares(GEN, SECRET, PARTICIPANTS_PK, quorum, total, false)

-- -- I.schema(SHARES)

-- assert( PVSS.verify_shares(GEN, quorum, total, SHARES) )

-- print(JSON.encode(SHARES))

-- RECONSTRUCTION

-- local dec
-- DEC = { }
-- for i=1, quorum do
--   table.insert(DEC, PVSS.decrypt_share
--   (GEN, PARTICIPANTS_SK[i], PARTICIPANTS_PK[i], SHARES))
-- end
-- VAL, IDX = PVSS.verify_decrypted_shares(GEN, DEC)

-- assert(
--   sha256(PVSS.pooling_shares(VAL, IDX, quorum))
--   ==
--   USABLE_SECRET
-- )
