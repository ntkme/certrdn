#include <gnutls/x509.h>
#include <stdio.h>

int certrdn_x509_crt_get_dn_by_oid(const char *filename, const char *oid, giovec_t *iovec) {
    gnutls_datum_t data;
    gnutls_x509_crt_t *certs;
    unsigned int size;
    int ret;

    iovec->iov_base= NULL;
    iovec->iov_len = 0;

    ret = gnutls_load_file(filename, &data);
    if (ret != GNUTLS_E_SUCCESS) {
        return ret;
    }

    for (gnutls_x509_crt_fmt_t format = GNUTLS_X509_FMT_DER; format <= GNUTLS_X509_FMT_PEM; ++format) {
        ret = gnutls_x509_crt_list_import2(&certs, &size, &data, format, 0);
        if (ret == GNUTLS_E_SUCCESS) {
            break;
        }
    }

    gnutls_free(data.data);

    if (ret != GNUTLS_E_SUCCESS) {
        return ret;
    }

    do {
        ret = gnutls_x509_crt_get_dn_by_oid(certs[0], oid, 0, 0, iovec->iov_base, &iovec->iov_len);
        if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
            iovec->iov_base = gnutls_malloc(iovec->iov_len + 1);
            if (iovec->iov_base == NULL) {
                ret = GNUTLS_E_MEMORY_ERROR;
            }
        }
    } while (ret == GNUTLS_E_SHORT_MEMORY_BUFFER);

    gnutls_free(certs);

    if (ret != GNUTLS_E_SUCCESS) {
        gnutls_free(iovec->iov_base);
    }

    return ret;
}

int main(int argc, char *argv[]) {
    giovec_t iovec;
    int exit_code = 0, ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s oid [pem...]\n", argv[0]);
        return 1;
    }

    for (int i = 2; i < argc; ++i) {
        ret = certrdn_x509_crt_get_dn_by_oid(argv[i], argv[1], &iovec);
        if (ret != GNUTLS_E_SUCCESS) {
            fprintf(stderr, "%s: %s\n", argv[i], gnutls_strerror(ret));
            exit_code = 1;
        } else {
            fprintf(stdout, "%s\n", (char *)iovec.iov_base);
            gnutls_free(iovec.iov_base);
        }
    }

    return exit_code;
}
