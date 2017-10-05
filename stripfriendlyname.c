#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

void rangedHexPrint(const unsigned char* buf, int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        printf("%02X ", buf[i]);
    }

    printf("\n");
}

int main(int argc, const char** argv)
{
	BIO* bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    BIO* in = NULL;
    BIO* out = NULL;
    PKCS12* pkcs12 = NULL;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int maclen;
    const char* pass;
    size_t passlen;
    STACK_OF(PKCS7) *asafes, *newsafes;
    STACK_OF(PKCS12_SAFEBAG) *bags;
    int i, j;

    if (argc < 4)
    {
        printf("Usage: %s pfxin pwd pfxout\n", argv[0]);
        return 1;
    }

    pass = argv[2];
    passlen = strlen(pass);

    if (!pass[0])
    {
        pass = NULL;
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    in = BIO_new_file(argv[1], "rb");

    if (!in)
    {
        ERR_print_errors(bio_err);
        return 2;
    }

    pkcs12 = d2i_PKCS12_bio(in, NULL);
    BIO_free(in);

    if (!pkcs12)
    {
        ERR_print_errors(bio_err);
        return 3;
    }

    if (!PKCS12_mac_present(pkcs12))
    {
        PKCS12_free(pkcs12);
        printf("No mac is present.\n");
        return 0;
    }

    if (!pass)
    {
        if (PKCS12_verify_mac(pkcs12, "", -1))
        {
            printf("Password is empty, not NULL.\n");
            pass = "";
        }
    }

    if (!PKCS12_verify_mac(pkcs12, pass, -1))
    {
        printf("MAC verification failed.\n");
        ERR_print_errors(bio_err);
        return 7;
    }

    if (!pass)
    {
        printf("Promoting NULL password to empty password\n");
        pass = "";
    }

    out = BIO_new_file(argv[3], "wb");

    if (!out)
    {
        ERR_print_errors(bio_err);
        return 11;
    }

    printf("Current mac:\n");
    rangedHexPrint(
        pkcs12->mac->dinfo->digest->data,
        pkcs12->mac->dinfo->digest->length);

    
    if ((asafes = PKCS12_unpack_authsafes(pkcs12)) == NULL)
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 4;
    }

    if ((newsafes = sk_PKCS7_new_null()) == NULL)
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 5;
    }

    for (i = 0; i < sk_PKCS7_num(asafes); i++)
    {
        PKCS7* p7 = sk_PKCS7_value(asafes, i);
        PKCS7* p7new;
        int bagnid = OBJ_obj2nid(p7->type);

        if (bagnid != NID_pkcs7_data)
        {
            sk_PKCS7_push(newsafes, p7);
            printf("Copying safe %d as-is\n", i);
            continue;
        }

        bags = PKCS12_unpack_p7data(p7);

        if (!bags)
        {
            ERR_print_errors(bio_err);
            sk_PKCS7_pop_free(asafes, PKCS7_free);
            PKCS12_free(pkcs12);
            return 5;
        }

        for (j = 0; j < sk_PKCS12_SAFEBAG_num(bags); j++)
        {
            PKCS12_SAFEBAG* bag = sk_PKCS12_SAFEBAG_value(bags, j);
            int bagnid = OBJ_obj2nid(bag->type);
            int attrLoc;
            
            if (bagnid != NID_pkcs8ShroudedKeyBag)
            {
                printf("Skipping bag (%d, %d) due to its type (%s)\n", i, j, OBJ_nid2sn(bagnid));
                continue;
            }

            attrLoc = X509at_get_attr_by_NID(bag->attrib, NID_friendlyName, -1);

            if (attrLoc < 0)
            {
                printf("No friendly name in bag (%d, %d)\n", i, j);
            }
            else
            {
                int postcount;
                int precount = sk_X509_ATTRIBUTE_num(bag->attrib);
                X509_ATTRIBUTE* friendlyName = X509at_delete_attr(bag->attrib, attrLoc);
                X509_ATTRIBUTE_free(friendlyName);
                postcount = sk_X509_ATTRIBUTE_num(bag->attrib);

                printf("Deleted friendly name in bag (%d, %d) (%d => %d)\n", i, j, precount, postcount);
            }
        }

        p7new = PKCS12_pack_p7data(bags);
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        sk_PKCS7_push(newsafes, p7new);        
    }

    if (!PKCS12_pack_authsafes(pkcs12, newsafes))
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 6;
    }

    if (!PKCS12_gen_mac(pkcs12, pass, passlen, mac, &maclen))
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 9;
    }

    if (!ASN1_OCTET_STRING_set(pkcs12->mac->dinfo->digest, mac, maclen))
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 10;
    }

    printf("New mac:\n");
    rangedHexPrint(mac, maclen);

    if (!PKCS12_verify_mac(pkcs12, pass, -1))
    {
        printf("New MAC verification failed.\n");
        ERR_print_errors(bio_err);
        return 7;
    }

    if (!i2d_PKCS12_bio(out, pkcs12))
    {
        ERR_print_errors(bio_err);
        PKCS12_free(pkcs12);
        return 12;
    }

    PKCS12_free(pkcs12);
    BIO_free(bio_err);
    BIO_free(bio_out);
    return 0;
}

