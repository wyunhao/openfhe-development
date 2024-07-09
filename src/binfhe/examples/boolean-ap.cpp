//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Example for the FHEW scheme using the AP bootstrapping
 */

#include "binfhecontext.h"

using namespace std;
using namespace lbcrypto;

int main() {
    // Sample Program: Step 1: Set CryptoContext

    BinFHEContext context = BinFHEContext();
    context.GenerateBinFHEContext(STD128, AP);
    LWEPrivateKey sk = context.KeyGen();
    context.BTKeyGen(sk);
  

    auto& RGSWParams = context.m_params->GetRingGSWParams();
    auto& LWEParams  = context.m_params->GetLWEParams();
    auto polyParams  = RGSWParams->GetPolyParams();


    uint32_t N       = LWEParams->GetN();
    NativeInteger Q  = LWEParams->GetQ();
    NativeVector m(N, Q);
    for (int i = 0; i < (int) N; i++) {
      m[i] = 0;
    }
    m[1] = 1;
    std::vector<NativePoly> res(2);
    // no need to do NTT as all coefficients of this poly are zero
    res[0] = NativePoly(polyParams, Format::EVALUATION, true);
    res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
    res[1].SetValues(std::move(m), Format::COEFFICIENT);
    res[1].SetFormat(Format::EVALUATION);

    // main accumulation computation
    // the following loop is the bottleneck of bootstrapping/binary gate
    // evaluation
    auto acc = std::make_shared<RLWECiphertextImpl>(std::move(res));

    std::vector<NativePoly>& accVec = acc->GetElements();

    accVec[0] = accVec[0].Transpose();
    accVec[0].SetFormat(Format::COEFFICIENT);
    accVec[1].SetFormat(Format::COEFFICIENT);

    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    
    NativeInteger b(0); // = Q / NativeInteger(8) + 1;
    b.ModAddFastEq(accVec[1][0], Q);

    auto ctExt = std::make_shared<LWECiphertextImpl>(std::move(accVec[0].GetValues()), std::move(b));
    // Modulus switching to a middle step Q'
    // auto ctMS = context.GetLWEScheme()->ModSwitch(LWEParams->GetqKS(), ctExt);
    // // Key switching
    // auto ctKS = context.GetLWEScheme()->KeySwitch(LWEParams, context.m_BTKey.KSkey, ctMS);
    
    
    // // Modulus switching
    // auto ct1 = context.Encrypt(sk, 1);
    // LWECiphertext final_lwe = context.GetLWEScheme()->ModSwitch(ct1->GetModulus(), ctKS);



    LWEPlaintext result;
    context.Decrypt(sk, ctExt, &result);


    std::cout << "Result = " << result << std::endl;



    // int party_size = 2;

    // vector<BinFHEContext> cc_list(party_size);
    // vector<LWEPrivateKey> sk_list(party_size);

    // for (int i = 0; i < party_size; i++) {
    //   cc_list[i] = BinFHEContext();
    //   cc_list[i].GenerateBinFHEContext(STD128, AP);
    //   sk_list[i] = cc_list[i].KeyGen();
    // }

    // std::cout << "Generating the bootstrapping keys..." << std::endl;

    // // Generate the bootstrapping keys (refresh and switching keys)

    // for (int i = 0; i < party_size; i++) {
    //   cc_list[i].BTKeyGen(sk_list[i]);
    // }

    // std::cout << "Completed the key generation." << std::endl;

    // // Sample Program: Step 3: Encryption

    // // Encrypt two ciphertexts representing Boolean True (1)
    // // By default, freshly encrypted ciphertexts are bootstrapped.
    // // If you wish to get a fresh encryption without bootstrapping, write
    // // auto   ct1 = cc.Encrypt(sk, 1, FRESH);
    // auto ct1 = cc_list[0].Encrypt(sk_list[0], 1);
    // auto ct2 = cc_list[0].Encrypt(sk_list[0], 1);

    // // Sample Program: Step 4: Evaluation

    // // Compute (1 AND 1) = 1; Other binary gate options are OR, NAND, and NOR

    // auto ctResult = cc_list[0].EvalBinGate(AND, ct1, ct2);

    // LWEPlaintext result;

    // cc_list[0].Decrypt(sk_list[0], ctResult, &result);

    // std::cout << "Result of encrypted computation of (1 AND 1) OR (1 AND (NOT 1)) = " << result << std::endl;

    return 0;
}
