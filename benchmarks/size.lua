
CLAIMS, REVOCS = test_many_issuance(1)
PROOFS = test_many_proofs(1, CLAIMS)

I.print({claims = CLAIMS[1],
         revocs = REVOCS[1],
         proofs = PROOFS[1]})

size = 0
for k,v in pairs(CLAIMS[1]) do
  size = size + #v:octet()
end

print('Size of a signed claim: '..size)


size = 0
for k,v in pairs(PROOFS[1]) do
  size = size + #v:octet()
end

print('Size of a signed proof: '..size)

size = 0
for k,v in pairs(REVOCS[1]) do
  size = size + #v:octet()
end

print('Size of a signed revocation: '..size)
