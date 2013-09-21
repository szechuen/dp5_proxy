#include <iostream>   
#include <time.h>

#define __cplusplussave __cplusplus
#undef __cplusplus
extern "C" {
#include <relic/relic.h>
}
#define __cplusplus __cplusplussave
         
using namespace std;

int main(void) {
	core_init();
	pc_param_set_any();    
	
	cout << fp_param_get() << BN_256 << endl;       
	
	g1_t g1;	
	g1_new(g1);
	g1_get_gen(g1);
	
	bn_t sk; /* secret key */
	bn_t n;
	
	bn_new(n);
	g1_get_ord(n);	/* order of G1 */
	
	bn_new(sk);
	
	do {
		bn_rand(sk, BN_POS, 2 * pc_param_level());
		bn_mod(sk, sk, n);		
	} while (bn_is_zero(sk));
	
	g1_t pk; /* public key */
	g1_new(pk);
	
	g1_mul_gen(pk, sk);    
	                   
	unsigned int epoch = 123456789;
	g2_t h; /* hash of epoch */	
	g2_new(h);                 
	g2_map(h, (unsigned char *) &epoch, sizeof(epoch));
	
	g2_t sig; /* signature */
	g2_new(sig);
	g2_mul(sig, h, sk);
	
	/* verify signature */
	gt_t e1;
	gt_t e2;
	
	gt_new(e1);
	gt_new(e2);
	       
	/* e1 = e(g_1, sig) */
	pc_map(e1, g1, sig);
	/* e2 = e(pk, h) */
	pc_map(e2, pk, h);
	
	if (gt_cmp(e1, e2) == CMP_EQ) {
		cout << "Success!" << endl;
	} else {
		cout << "Failure!!" << endl;
	}        
	                               
	int LOOPS = 10000;           
	clock_t start = clock();
	for (int i = 0; i < LOOPS; i++) {
		g1_t g1gen;
		gt_t e;
		
		g1_new(g1gen);
		g1_get_gen(g1gen);
		
		gt_new(e);
		
		pc_map(e, g1gen, sig);
		
		g1_free(g1gen);
		gt_free(e);
	}
	clock_t finish = clock();
	
	cout << ((finish - start)*1000.0)/LOOPS/CLOCKS_PER_SEC << "ms per loop" << endl;
		
	return 0;
}