
class PrimeField():
    def __init__(self, modulus):
        # Quick primality test
        assert pow(2, modulus, modulus) == 2
        self.modulus = modulus

    def add(self, x, y):
        return (x+y) % self.modulus

    def sub(self, x, y):
        return (x-y) % self.modulus

    def mul(self, x, y):
        return (x*y) % self.modulus

# Modular inverse using the extended Euclidean algorithm
def inv(self, a):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % self.modulus, self.modulus
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % self.modulus

def multi_inv(self, values):
    partials = [1]
    for i in range(len(values)):
        partials.append(self.mul(partials[-1], values[i] or 1))
    inv = self.inv(partials[-1])
    outputs = [0] * len(values)
    for i in range(len(values), 0, -1):
        outputs[i-1] = self.mul(partials[i-1], inv) if values[i-1] else 0
        inv = self.mul(inv, values[i-1] or 1)
    return outputs

# Evaluate a polynomial at a point
def eval_poly_at(self, p, x):
    y = 0
    power_of_x = 1
    for i, p_coeff in enumerate(p):
        y += power_of_x * p_coeff
        power_of_x = (power_of_x * x) % self.modulus
    return y % self.modulus

# Build a polynomial that returns 0 at all specified xs
def zpoly(self, xs):
    root = [1]
    for x in xs:
        root.insert(0, 0)
        for j in range(len(root)-1):
            root[j] -= root[j+1] * x
    return [x % self.modulus for x in root]

def lagrange_interp(self, xs, ys):
    # Generate master numerator polynomial, eg. (x - x1) * (x - x2) * ... * (x - xn)
    root = self.zpoly(xs)

    # Generate per-value numerator polynomials, eg. for x=x2,
    # (x - x1) * (x - x3) * ... * (x - xn), by dividing the master
    # polynomial back by each x coordinate
    nums = [self.div_polys(root, [-x, 1]) for x in xs]

    # Generate denominators by evaluating numerator polys at each x
    denoms = [self.eval_poly_at(nums[i], xs[i]) for i in range(len(xs))]
    invdenoms = self.multi_inv(denoms)

    # Generate output polynomial, which is the sum of the per-value numerator
    # polynomials rescaled to have the right y values
    b = [0 for y in ys]
    for i in range(len(xs)):
        yslice = self.mul(ys[i], invdenoms[i])
        for j in range(len(ys)):
            if nums[i][j] and ys[i]:
                b[j] += nums[i][j] * yslice
    return [x % self.modulus for x in b]

def fft(vals, modulus, root_of_unity):
    if len(vals) == 1:
        return vals
    L = fft(vals[::2], modulus, pow(root_of_unity, 2, modulus))
    R = fft(vals[1::2], modulus, pow(root_of_unity, 2, modulus))
    o = [0 for i in vals]
    for i, (x, y) in enumerate(zip(L, R)):
        y_times_root = y*pow(root_of_unity, i, modulus)
        o[i] = (x+y_times_root) % modulus
        o[i+len(L)] = (x-y_times_root) % modulus
    return o

def inv_fft(vals, modulus, root_of_unity):
    f = PrimeField(modulus)
    # Inverse FFT
    invlen = f.inv(len(vals))
    return [(x*invlen) % modulus for x in
            fft(vals, modulus, f.inv(root_of_unity))]


# Calculate the set of x coordinates
xs = get_power_cycle(root_of_unity, modulus)

column = []
for i in range(len(xs)//4):
    x_poly = f.lagrange_interp_4( 
        [xs[i+len(xs)*j//4] for j in range(4)],
        [values[i+len(values)*j//4] for j in range(4)],
    )
    column.append(f.eval_poly_at(x_poly, special_x))

m2 = merkelize(column)

# Pseudo-randomly select y indices to sample
# (m2[1] is the Merkle root of the column)
ys = get_pseudorandom_indices(m2[1], len(column), 40)

# Compute the Merkle branches for the values in the polynomial and the column
branches = []
for y in ys:
    branches.append([mk_branch(m2, y)] +
                    [mk_branch(m, y + (len(xs) // 4) * j) for j in range(4)])

assert steps <= 2**32 // extension_factor
assert is_a_power_of_2(steps) and is_a_power_of_2(len(round_constants))
assert len(round_constants) < steps

# Generate the computational trace
computational_trace = [inp]
for i in range(steps-1):
    computational_trace.append((computational_trace[-1]**3 + round_constants[i % len(round_constants)]) % modulus)
output = computational_trace[-1]

computational_trace_polynomial = inv_fft(computational_trace, modulus, subroot)
p_evaluations = fft(computational_trace_polynomial, modulus, root_of_unity)

skips2 = steps // len(round_constants)
constants_mini_polynomial = fft(round_constants, modulus, f.exp(subroot, skips2), inv=True)
constants_polynomial = [0 if i % skips2 else constants_mini_polynomial[i//skips2] for i in range(steps)]
constants_mini_extension = fft(constants_mini_polynomial, modulus, f.exp(root_of_unity, skips2))

# Create the composed polynomial such that
# C(P(x), P(g1*x), K(x)) = P(g1*x) - P(x)**3 - K(x)
c_of_p_evaluations = [(p_evaluations[(i+extension_factor)%precision] -
                          f.exp(p_evaluations[i], 3) -
                          constants_mini_extension[i % len(constants_mini_extension)])
                      % modulus for i in range(precision)]
print('Computed C(P, K) polynomial')

# Compute D(x) = Q(x) / Z(x)
# Z(x) = (x^steps - 1) / (x - x_atlast_step)
z_num_evaluations = [xs[(i * steps) % precision] - 1 for i in range(precision)]
z_num_inv = f.multi_inv(z_num_evaluations)
z_den_evaluations = [xs[i] - last_step_position for i in range(precision)]
d_evaluations = [cp * zd * zni % modulus for cp, zd, zni in zip(c_of_p_evaluations, z_den_evaluations, z_num_inv)]
print('Computed D polynomial')

# Compute interpolant of ((1, input), (x_atlast_step, output))
interpolant = f.lagrange_interp_2([1, last_step_position], [inp, output])
i_evaluations = [f.eval_poly_at(interpolant, x) for x in xs]

zeropoly2 = f.mul_polys([-1, 1], [-last_step_position, 1])
inv_z2_evaluations = f.multi_inv([f.eval_poly_at(quotient, x) for x in xs])

# B = (P - I) / Z2
b_evaluations = [((p - i) * invq) % modulus for p, i, invq in zip(p_evaluations, i_evaluations, inv_z2_evaluations)]
print('Computed B polynomial')

# Compute their Merkle roots
mtree = merkelize([pval.to_bytes(32, 'big') +
                   dval.to_bytes(32, 'big') +
                   bval.to_bytes(32, 'big') for
                   pval, dval, bval in zip(p_evaluations, d_evaluations, b_evaluations)])
print('Computed hash root')

k1 = int.from_bytes(blake(mtree[1] + b'\x01'), 'big')
k2 = int.from_bytes(blake(mtree[1] + b'\x02'), 'big')
k3 = int.from_bytes(blake(mtree[1] + b'\x03'), 'big')
k4 = int.from_bytes(blake(mtree[1] + b'\x04'), 'big')

# Compute the linear combination. We don't even bother calculating it
# in coefficient form; we just compute the evaluations
root_of_unity_to_the_steps = f.exp(root_of_unity, steps)
powers = [1]
for i in range(1, precision):
    powers.append(powers[-1] * root_of_unity_to_the_steps % modulus)

l_evaluations = [(d_evaluations[i] +
                  p_evaluations[i] * k1 + p_evaluations[i] * k2 * powers[i] +
                  b_evaluations[i] * k3 + b_evaluations[i] * powers[i] * k4) % modulus
                  for i in range(precision)]

# Do some spot checks of the Merkle tree at pseudo-random coordinates, excluding
# multiples of `extension_factor`
branches = []
samples = spot_check_security_factor
positions = get_pseudorandom_indices(l_mtree[1], precision, samples,
                                     exclude_multiples_of=extension_factor)
for pos in positions:
    branches.append(mk_branch(mtree, pos))
    branches.append(mk_branch(mtree, (pos + skips) % precision))
    branches.append(mk_branch(l_mtree, pos))
print('Computed %d spot checks' % samples)

o = [mtree[1],
     l_mtree[1],
     branches,
     prove_low_degree(l_evaluations, root_of_unity, steps * 2, modulus, exclude_multiples_of=extension_factor)]

for i, pos in enumerate(positions):
    x = f.exp(G2, pos)
    x_to_the_steps = f.exp(x, steps)
    mbranch1 =  verify_branch(m_root, pos, branches[i*3])
    mbranch2 =  verify_branch(m_root, (pos+skips)%precision, branches[i*3+1])
    l_of_x = verify_branch(l_root, pos, branches[i*3 + 2], output_as_int=True)

    p_of_x = int.from_bytes(mbranch1[:32], 'big')
    p_of_g1x = int.from_bytes(mbranch2[:32], 'big')
    d_of_x = int.from_bytes(mbranch1[32:64], 'big')
    b_of_x = int.from_bytes(mbranch1[64:], 'big')

    zvalue = f.div(f.exp(x, steps) - 1,
                   x - last_step_position)
    k_of_x = f.eval_poly_at(constants_mini_polynomial, f.exp(x, skips2))

    # Check transition constraints Q(x) = Z(x) * D(x)
    assert (p_of_g1x - p_of_x ** 3 - k_of_x - zvalue * d_of_x) % modulus == 0

    # Check boundary constraints B(x) * Z2(x) + I(x) = P(x)
    interpolant = f.lagrange_interp_2([1, last_step_position], [inp, output])
    zeropoly2 = f.mul_polys([-1, 1], [-last_step_position, 1])
    assert (p_of_x - b_of_x * f.eval_poly_at(zeropoly2, x) -
            f.eval_poly_at(interpolant, x)) % modulus == 0

    # Check correctness of the linear combination
    assert (l_of_x - d_of_x -
            k1 * p_of_x - k2 * p_of_x * x_to_the_steps -
            k3 * b_of_x - k4 * b_of_x * x_to_the_steps) % modulus == 0

