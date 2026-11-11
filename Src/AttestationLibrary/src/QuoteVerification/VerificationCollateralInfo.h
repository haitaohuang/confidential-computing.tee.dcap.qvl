/*
 * Copyright (C) 2025 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SGXECDSAATTESTATION_VERIFICATIONCOLLATERALINFO_H
#define SGXECDSAATTESTATION_VERIFICATIONCOLLATERALINFO_H

#include <array>
#include <ctime>
#include <string>
#include <vector>
#include "SgxEcdsaAttestation/AttestationParsers.h"
#include "SgxEcdsaAttestation/QuoteVerification.h"
#include "Utils/Optional.h"
#include "Utils/TimeUtils.h"

namespace intel { namespace sgx { namespace dcap {

struct ComponentTcbInfo
{
    std::time_t date{0};
    Status status{STATUS_TCB_NOT_SUPPORTED};
};

struct ComponentTcbEvaluation
{
    uint32_t flags{0};
    ComponentTcbInfo platform{};
    ComponentTcbInfo tdxModule{};
    ComponentTcbInfo qe{};
    std::array<uint8_t, 16> sgxTcbComponents{};
    std::array<uint8_t, 16> tdxTcbComponents{};
    uint16_t pceSvn{0};
    uint8_t tdxModuleSvn{0};
    uint16_t qeSvn{0};
};

class VerificationCollateralInfo
{
public:
    explicit VerificationCollateralInfo(uint16_t version = 2);
    void addLaunchInfo(const std::time_t& tcbDate, const std::vector<std::string>& advisoryIds, const std::string& tcbStatus, const ComponentTcbEvaluation& components);
    void addCurrentInfo(const std::time_t& tcbDate, const std::vector<std::string>& advisoryIds, const std::string& tcbStatus, const ComponentTcbEvaluation& components);
    void addTcbInfoData(const parser::json::TcbInfo& tcbInfo);
    void addEnclaveIdentityData(const parser::json::EnclaveIdentity& enclaveIdentity);
    std::vector<uint8_t> aggregateDataAndParseToVec();
    bool isFilled() const;
    void setFilled();
protected:
    int _id;
    int _version;
    std::vector<time_t> _issueDates{};
    std::vector<time_t> _nextUpdates{};
    std::vector<unsigned  int> _tcbEvalNumbers{};
    std::time_t _launchTcbDate{0};
    std::time_t _currentTcbDate{0};
    std::set<std::string> _launchAdvisoryIds{};
    std::set<std::string> _currentAdvisoryIds{};
    std::string _launchTcbStatus{};
    std::string _currentTcbStatus{};
    ComponentTcbEvaluation _launchComponents{};
    ComponentTcbEvaluation _currentComponents{};
    uint32_t _tcbInfoEvalNumber{0};
    uint32_t _qeEvalNumber{0};

    bool _isFilled = true;
};

/**
 * Exception when size of VerificationCollateralInfo structure is bigger than expected
 */
class VerCollInfoSizeException : public std::logic_error
{
public:
    using std::logic_error::logic_error;
};

}}}

#endif //SGXECDSAATTESTATION_VERIFICATIONCOLLATERALINFO_H
