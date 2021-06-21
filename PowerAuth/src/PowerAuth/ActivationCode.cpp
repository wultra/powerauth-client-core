/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <PowerAuth/ActivationCode.h>
#include <cc7/Base64.h>
#include <cc7/Base32.h>
#include "utils/CRC16.h"

namespace com
{
namespace wultra
{
namespace powerAuth
{
    
    // MARK: - ActivationCode -
    
    bool ActivationCode::hasSignature() const
    {
        return !activationSignature.empty();
    }
    
    // MARK: - ActivationCodeUtil -
    
    // Parser
    
    bool ActivationCodeUtil::parseActivationCode(const std::string &activation_code_str, ActivationCode &out_activation_code)
    {
        // At first, look for #
        auto hash_pos = activation_code_str.find('#');
        auto has_signature = hash_pos != std::string::npos;
        if (has_signature) {
            // split activationCode to code and signature
            out_activation_code.activationCode = activation_code_str.substr(0, hash_pos);
            out_activation_code.activationSignature = activation_code_str.substr(hash_pos + 1);
            // validate Base64 signature
            if (!validateSignature(out_activation_code.activationSignature)) {
                return false;
            }
        } else {
            // use a whole input string as a code
            out_activation_code.activationCode = activation_code_str;
            out_activation_code.activationSignature.clear();
        }
        // Now validate just the code
        return validateActivationCode(out_activation_code.activationCode);
    }
    
    static const std::string RECOVERY_QR_MARKER("R:");
    
    bool ActivationCodeUtil::parseRecoveryCode(const std::string &recovery_code_str, ActivationCode &out_activation_code)
    {
        std::string code_to_test;
        auto recovery_marker_pos = recovery_code_str.find(RECOVERY_QR_MARKER);
        if (recovery_marker_pos != std::string::npos) {
            if (recovery_marker_pos != 0) {
                return false;   // "R:" is not at the beginning of string
            }
            code_to_test = recovery_code_str.substr(2);
        } else {
            code_to_test = recovery_code_str;
        }
        if (!parseActivationCode(code_to_test, out_activation_code)) {
            return false;
        }
        return out_activation_code.hasSignature() == false;
    }
    
    
    // Validations

    bool ActivationCodeUtil::validateTypedCharacter(cc7::U32 uc)
    {
        return (uc >= 'A' && uc <= 'Z') || (uc >= '2' && uc <= '7');
    }
    
    
    cc7::U32 ActivationCodeUtil::validateAndCorrectTypedCharacter(cc7::U32 uc)
    {
        // If character is already valid, then return it directly
        if (validateTypedCharacter(uc)) {
            return uc;
        }
        // autocorrect
        if (uc >= 'a' && uc <= 'z') {
            return uc - ('a' - 'A');    // lower->upper case
        } else  if (uc == '0') {
            return 'O';                 // 0 -> O
        } else if (uc == '1') {
            return 'I';                 // 1 -> I
        }
        // character is invalid
        return 0;
    }
    
    
    bool ActivationCodeUtil::validateActivationCode(const std::string &code)
    {
        // ABCDE-ABCDE-ABCDE-ABCDE
        if (code.length() != 23) {
            return false;
        }
        std::string code_base32;
        code_base32.reserve(20);
        for (size_t i = 0; i < code.length(); i++) {
            auto c = code[i];
            // validate dash at right position
            if ((i % 6) == 5) {
                if (c != '-') {
                    return false;
                }
            } else {
                code_base32.push_back(c);
            }
        }
        cc7::ByteArray code_bytes;
        if (!cc7::Base32_Decode(code_base32, false, code_bytes)) {
            // Not a valid Base32 string
            return false;
        }
        // Finally, validate CRC-16 checksum
        return utils::CRC16_Validate(code_bytes);
    }
    
    
    bool ActivationCodeUtil::validateSignature(const std::string &signature)
    {
        cc7::ByteArray foo_data;
        if (cc7::Base64_Decode(signature, 0, foo_data)) {
            return !foo_data.empty();
        }
        return false;
    }
    
    
    bool ActivationCodeUtil::validateRecoveryCode(const std::string &recovery_code, bool allow_r_prefix)
    {
        if (recovery_code.find(RECOVERY_QR_MARKER) == std::string::npos) {
            return validateActivationCode(recovery_code);
        }
        return allow_r_prefix && validateActivationCode(recovery_code.substr(2));
    }
    
    
    bool ActivationCodeUtil::validateRecoveryPuk(const std::string &recovery_puk)
    {
        if (recovery_puk.length() != 10) {
            return false;
        }
        for (size_t i = 0; i < recovery_puk.length(); i++) {
            auto c = recovery_puk[i];
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }
    
} // com::wultra::powerAuth
} // com::wultra
} // com
