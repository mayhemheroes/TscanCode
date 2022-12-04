#include <stdint.h>
#include <stdio.h>
#include <climits>

#include "FuzzedDataProvider.h"
#include "path.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    Path::simplifyPath(str);

    return 0;
}