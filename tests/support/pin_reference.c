/* Deterministic fixture generator. Build with -I <working UxPlay lib> and OpenSSL.
 * Includes that implementation directly to cross-check Apple's SRP variant.
 * No network, credentials or device identity are used. */
#include "srp.c"

static void out(const char *label, const unsigned char *bytes, int length) {
    printf("%s=", label);
    for (int i=0; i<length; ++i) printf("%02x", bytes[i]);
    putchar('\n');
}
static void gcm(const unsigned char *key, const unsigned char *iv, const unsigned char *plain,
                unsigned char *encrypted, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int length, final;
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)==1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)==1);
    assert(EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv)==1);
    assert(EVP_EncryptUpdate(ctx,encrypted,&length,plain,32)==1);
    assert(EVP_EncryptFinal_ex(ctx,encrypted+length,&final)==1);
    assert(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag)==1);
    EVP_CIPHER_CTX_free(ctx);
}
int main(void) {
    const char *user="A1B2C3D4E5F6", *pin="1234";
    unsigned char salt[16], secret_b[32], secret_a[32], client_pk[32], server_pk[32];
    for(int i=0;i<16;i++) salt[i]=(unsigned char)(i+1);
    for(int i=0;i<32;i++) { secret_b[i]=(unsigned char)(i+33); secret_a[i]=(unsigned char)(i+65); }
    /* RFC8032 Ed25519 public-key fixtures, not live identity. */
    const char *client_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const char *server_hex="3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    for(int i=0;i<32;i++) { unsigned int c,s; sscanf(client_hex+2*i,"%2x",&c);sscanf(server_hex+2*i,"%2x",&s);client_pk[i]=(unsigned char)c;server_pk[i]=(unsigned char)s; }
    for(int variant=0;variant<3;variant++) {
        if(variant) salt[0]=0; /* Minimal-bignum salt hashing, not padded salt. */
        if(variant==2) { memset(salt,0,16);memset(secret_a,0,32);secret_a[31]=1; }
        printf("CASE=%d\n",variant); out("salt",salt,16);out("b",secret_b,32);out("a",secret_a,32);
        NGConstant *ng=new_ng(SRP_NG_2048,NULL,NULL); BN_CTX *ctx=BN_CTX_new();
        BIGNUM *s=BN_bin2bn(salt,16,NULL), *a=BN_bin2bn(secret_a,32,NULL);
        BIGNUM *x=calculate_x(SRP_SHA1,s,user,(const unsigned char *)pin,4);
        BIGNUM *v=BN_new(),*A=BN_new(),*B=NULL,*S=BN_new(),*t=BN_new(),*exponent=BN_new();
        BN_mod_exp(v,ng->g,x,ng->N,ctx); BN_mod_exp(A,ng->g,a,ng->N,ctx);
        unsigned char vb[256],ab[256];int vl=BN_bn2bin(v,vb),al=BN_bn2bin(A,ab),bl=0; const unsigned char *bb=NULL;
        srp_create_server_ephemeral_key(SRP_SHA1,SRP_NG_2048,vb,vl,secret_b,32,&bb,&bl,NULL,NULL,1);
        B=BN_bin2bn(bb,bl,NULL);BIGNUM *k=H_nn_rfc5054(SRP_SHA1,ng->N,ng->N,ng->g);
        BIGNUM *u=H_nn_rfc5054(SRP_SHA1,ng->N,A,B);
        BN_mod_mul(t,k,v,ng->N,ctx);BN_mod_sub(t,B,t,ng->N,ctx);
        BN_mul(exponent,u,x,ctx);BN_add(exponent,exponent,a);BN_mod_exp(S,t,exponent,ng->N,ctx);
        unsigned char K[40],M1[20],M2[20];hash_session_key(SRP_SHA1,S,K);
        calculate_M(SRP_SHA1,ng,M1,user,s,A,B,K);calculate_H_AMK(SRP_SHA1,M2,A,M1,K);
        const unsigned char *verify_b=NULL,*verify_m=NULL;int verify_bl=0;
        struct SRPVerifier *verify=srp_verifier_new(SRP_SHA1,SRP_NG_2048,user,salt,16,vb,vl,ab,al,secret_b,32,&verify_b,&verify_bl,NULL,NULL,1);
        srp_verifier_verify_session(verify,M1,&verify_m);assert(srp_verifier_is_authenticated(verify));assert(memcmp(verify_m,M2,20)==0);
        out("A",ab,al);out("B",bb,bl);out("K",K,40);out("M1",M1,20);out("M2",M2,20);
        unsigned char digest[64],key[16],iv[16],epk[32],tag[16];
        EVP_MD_CTX *md=EVP_MD_CTX_new(); unsigned int dl;
        EVP_DigestInit_ex(md,EVP_sha512(),NULL);EVP_DigestUpdate(md,"Pair-Setup-AES-Key",strlen("Pair-Setup-AES-Key"));EVP_DigestUpdate(md,K,40);EVP_DigestFinal_ex(md,digest,&dl);memcpy(key,digest,16);
        EVP_DigestInit_ex(md,EVP_sha512(),NULL);EVP_DigestUpdate(md,"Pair-Setup-AES-IV",strlen("Pair-Setup-AES-IV"));EVP_DigestUpdate(md,K,40);EVP_DigestFinal_ex(md,digest,&dl);memcpy(iv,digest,16);
        iv[15]++;gcm(key,iv,client_pk,epk,tag);out("client_epk",epk,32);out("client_tag",tag,16);
        iv[15]++;gcm(key,iv,server_pk,epk,tag);out("server_epk",epk,32);out("server_tag",tag,16);
        EVP_MD_CTX_free(md);srp_verifier_delete(verify);free((void*)bb);
        BN_free(s);BN_free(a);BN_free(x);BN_free(v);BN_free(A);BN_free(B);BN_free(S);BN_free(t);BN_free(exponent);BN_free(k);BN_free(u);BN_CTX_free(ctx);delete_ng(ng);
    }
    return 0;
}
