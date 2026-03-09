/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef JSVM_DFX_API_H_
#define JSVM_DFX_API_H_
#include <cstddef>
#include <cstdint>

constexpr uint16_t FUNCTIONNAME_MAX = 1024;
constexpr uint16_t URL_MAX = 1024;
struct JsvmFunction {
    char functionName[FUNCTIONNAME_MAX]; // fucntion name
    uint32_t offsetInFunction;           // pc offset in function
    char url[URL_MAX];                   // js file path
    int32_t line;                        // line start from 1
    int32_t column;                      // column start from 1
};

struct JsStepParam {
    uintptr_t* fp;
    uintptr_t* sp;
    uintptr_t* pc;
    bool* isJsFrame;

    JsStepParam(uintptr_t* fp, uintptr_t* sp, uintptr_t* pc, bool* isJsFrame)
        : fp(fp), sp(sp), pc(pc), isJsFrame(isJsFrame)
    {}
};

typedef bool (*ReadMemFunc)(void* ctx, uintptr_t addr, uintptr_t* val);

extern "C" int step_jsvm(void* ctx, ReadMemFunc readMem, JsStepParam* frame);

extern "C" int create_jsvm_extractor(uintptr_t* extractorPtr, uint32_t pid);

extern "C" int destroy_jsvm_extractor(uintptr_t extractor);

extern "C" int jsvm_parse_js_frame_info(uintptr_t pc, uintptr_t extractor, JsvmFunction* jsvmFunction);

#endif