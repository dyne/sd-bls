
-- how many to test and how much increment
TOTAL = 160
STEP = 10
TOTAL = TOTAL + STEP -- off by one fix

BBS = require 'crypto_bbs'
function keygen(ctx)
    local res = { sk = BBS.keygen(ctx) }
    res.pk = BBS.sk2pk(res.sk)
    return res
end
function sign(ctx, keys, obj)
    return BBS.sign(ctx, keys.sk, keys.pk, nil, obj)
end
function verify(ctx, pk, sig, obj)
    return BBS.verify(ctx, pk, sig, nil, obj)
end
function create_proof(ctx, pk, sig, arr, disc)
    return BBS.proof_gen(ctx, pk, sig, nil, HEAD, arr, disc)
end
function verify_proof(ctx, pk, proof, arr, disc)
    return BBS.proof_verify(ctx, pk, proof, nil, HEAD, arr, disc)
end
function disclosed_messages(arr, indexes)
    local res = { }
    for k,v in pairs(indexes) do
        table.insert(res,arr[v])
    end
    return res
end
B3 = BBS.ciphersuite'shake256'

printerr "sign+verify shake256 "
local SIGN_T = { }
local PROVE_T = { }
local VERIFY_T = { }
for i=STEP,TOTAL,STEP do
  printerr(i.." ")
  local keys = keygen(B3)
  local messages = { }
  for c=1,i,1 do
      table.insert(messages, O.random(512))
  end
  collectgarbage'collect'
  collectgarbage'collect'

  local start = os.clock()
  local signed = sign(B3, keys, messages)
  table.insert(SIGN_T, os.clock() - start)

  -- prove all claims
  local indexes = { }
  for i=1,#messages do table.insert(indexes, i) end

  local start = os.clock()
  local proof = create_proof(B3, keys.pk, signed, messages, indexes)
  table.insert(PROVE_T, os.clock() - start)

  local disclosed = disclosed_messages(messages, indexes)
  local start = os.clock()
  assert( verify_proof(B3, keys.pk, proof, disclosed, indexes) )
  table.insert(VERIFY_T, os.clock() - start)

  collectgarbage'collect'
  collectgarbage'collect'

end

print("CLAIMS \t ISSUE \t PROVE \t VERIFY")
for i=1,(TOTAL/STEP),1 do
  write(i*STEP)
  write(' \t ')
  write(SIGN_T[i])
  write(' \t ')
  write(PROVE_T[i])
  write(' \t ')
  write(VERIFY_T[i])
  write('\n')
end
