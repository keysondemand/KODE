import os, sys, math, json, re

from charm.toolbox.ecgroup      import ECGroup, ZR, G
from charm.toolbox.eccurve      import secp256k1, prime192v1,prime192v2
from charm.core.math.integer    import randomBits
from charm.core.math.integer    import *

import numpy as np 

sys.path += ['./','../']

from conf.groupparam  import * 

p = group256.order()
q = group283.order()

from decimal import *
import math

getcontext().prec = 256
num = Decimal(int(p)) / Decimal(int(q))

print("num", num)

print("pqratio:", int(p)/int(q))

