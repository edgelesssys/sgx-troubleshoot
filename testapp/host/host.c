#include <openenclave/host.h>
#include <stdio.h>
#include "helloworld_u.h"

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
        return 1;
    }

    setenv("OE_LOG_LEVEL", "WARNING", 0);

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_helloworld_enclave(
        argv[1],
        OE_ENCLAVE_TYPE_AUTO,
        OE_ENCLAVE_FLAG_DEBUG_AUTO,
        NULL,
        0,
        &enclave);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        return 1;
    }

    int res = 0;
    result = enclave_helloworld(enclave, &res);
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        return 1;
    }

    return res;
}
