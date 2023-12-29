#include "../src/HEAAN.h"
#include "../src/Ciphertext.h"
#include "../src/EvaluatorUtils.h"
#include "../src/Ring.h"
#include "../src/Scheme.h"
#include "../src/SchemeAlgo.h"
#include "../src/SecretKey.h"
#include "../src/StringUtils.h"
#include "../src/TimeUtils.h"
#include "../src/SerializationUtils.h"

using namespace std;
using namespace heean;
using namespace NTL;

class InvSqRoot {
    public:
        Ciphertext SqRoot(Ciphertext x, int d, SecretKey &secretKey, Scheme &scheme, long logp, long logq);

        Ciphertext MinFunc(Ciphertext x, Ciphertext y, int d, SecretKey &secretKey, Scheme &scheme, long logp, long logq);

        Ciphertext MaxFunc(Ciphertext x, Ciphertext y, int d, SecretKey &secretKey, Scheme &scheme, long logp, long logq);

        Ciphertext PLU(Ciphertext x, SecretKey &secretKey, Scheme &scheme, long logp, long logq);

        Ciphertext ApproxTanh(Ciphertext x, int length, SecretKey &secretKey, Scheme &scheme, long logp, long logq);    
};