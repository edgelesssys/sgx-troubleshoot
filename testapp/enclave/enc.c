#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define ERR_GET_LOCAL_REPORT 2
#define ERR_VERIFY_LOCAL_REPORT 4
#define ERR_GET_REMOTE_REPORT 8
#define ERR_VERIFY_REMOTE_REPORT 16

static bool _has_err(oe_result_t res, const char* msg, int* err, int val)
{
    if (res == OE_OK)
        return false;
    printf("ERROR: %s: %s\n", msg, oe_result_str(res));
    *err |= val;
    return true;
}

static int _test_local_attestation(void)
{
    int err = 0;

    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_result_t res =
        oe_get_report_v2(0, NULL, 0, NULL, 0, &report, &report_size);
    if (_has_err(res, "get local report 1", &err, ERR_GET_LOCAL_REPORT))
        return err;

    printf("CPUSVN: ");
    for (size_t i = 16; i < 32; ++i)
        printf("%02x", report[i]);
    printf("\n");

    void* target = NULL;
    size_t target_size = 0;
    res = oe_get_target_info_v2(report, report_size, &target, &target_size);
    oe_free_report(report);
    if (_has_err(res, "get target info", &err, ERR_GET_LOCAL_REPORT))
        return err;

    res = oe_get_report_v2(
        0, NULL, 0, target, target_size, &report, &report_size);
    oe_free_target_info(target);
    if (_has_err(res, "get local report 2", &err, ERR_GET_LOCAL_REPORT))
        return err;

    res = oe_verify_report(report, report_size, NULL);
    oe_free_report(report);
    _has_err(res, "verify local report", &err, ERR_VERIFY_LOCAL_REPORT);

    return err;
}

static int _test_remote_attestation(void)
{
    int err = 0;

    uint8_t* report = NULL;
    size_t report_size = 0;
    oe_result_t res = oe_get_report_v2(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        0,
        NULL,
        0,
        &report,
        &report_size);
    if (_has_err(res, "get remote report", &err, ERR_GET_REMOTE_REPORT))
        return err;

    oe_claim_t* claims = NULL;
    size_t claims_length = 0;
    res = oe_verify_evidence(
        NULL, report, report_size, NULL, 0, NULL, 0, &claims, &claims_length);
    oe_free_report(report);
    printf("VERIFYRESULT: %s\n", oe_result_str(res));
    if (res != OE_TCB_LEVEL_INVALID &&
        _has_err(res, "verify remote report", &err, ERR_VERIFY_REMOTE_REPORT))
    {
        oe_free_claims(claims, claims_length);
        return err;
    }

    for (size_t i = 0; i < claims_length; ++i)
    {
        if (strcmp(claims[i].name, OE_CLAIM_TCB_STATUS) == 0)
        {
            printf("TCBSTATUS: %d\n", *(int*)claims[i].value);
            break;
        }
    }

    oe_free_claims(claims, claims_length);

    return err;
}

int enclave_helloworld(void)
{
    int err = _test_local_attestation();
    err |= _test_remote_attestation();
    return err;
}
