/* Minimal PAM app: authenticate <user> with a fixed <password> against <service>, print the code.
   Used to drive the real PAM stack for the duress end-to-end test. */
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static const char *g_pw;
static int conv_fn(int n, const struct pam_message **m, struct pam_response **resp, void *d){
    (void)m;(void)d;
    struct pam_response *r = calloc(n, sizeof(*r));
    for(int i=0;i<n;i++){ r[i].resp=strdup(g_pw); r[i].resp_retcode=0; }
    *resp=r; return PAM_SUCCESS;
}
int main(int argc,char**argv){
    if(argc<4){fprintf(stderr,"usage: %s <service> <user> <password>\n",argv[0]);return 2;}
    g_pw=argv[3];
    struct pam_conv c={conv_fn,NULL};
    pam_handle_t *ph=NULL;
    int rc=pam_start(argv[1],argv[2],&c,&ph);
    if(rc!=PAM_SUCCESS){printf("pam_start FAILED rc=%d\n",rc);return 3;}
    rc=pam_authenticate(ph,0);
    printf("pam_authenticate -> rc=%d (%s)\n",rc,pam_strerror(ph,rc));
    pam_end(ph,rc);
    return rc;
}
