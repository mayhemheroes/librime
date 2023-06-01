#include <stdint.h>
#include <stdio.h>
#include <climits>
#include "utilities.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    std::string str2 = provider.ConsumeRandomLengthString();
    rime::CompareVersionString(str, str2);
    return 0;
}
