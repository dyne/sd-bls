-- Issuer's keyring hardcoded 0x0 seed
A = {sk = BIG.new(sha256(OCTET.zero(32)))}
A.pk = G2*A.sk

print'SD-BLS size measurements'

fakes = generate_fake_claims(1)
CLAIM, REVOC = issuer_sign(A.sk, fakes)
local disclose = { }
for k,v in pairs(CLAIM) do
  I.schema({signed_claim = v})
  print('signed claim total: '.. #v.H+ #v.r+ #v.s:octet() ..' bytes')
  table.insert(disclose, k)
end
PROOF = holder_prove(CLAIM, disclose)

for k,v in pairs(PROOF) do
  I.schema({proof = v})
  print('one-time-proof total: '..
        #v.H + #v.c:octet() + #v.p + #v.r + #v.s:octet()
        ..' bytes (exclude content and session timestamp)')
end

for k,v in pairs(REVOC) do
  I.schema({[k] = v})
  print('revocation total: '..
        #k + #v
        ..' bytes')
end
